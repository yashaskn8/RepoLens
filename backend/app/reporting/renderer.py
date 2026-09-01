"""Deterministic, plain-text-only ReportLab renderer for ReportDocument."""

from dataclasses import dataclass
from pathlib import Path
import re
import textwrap
import unicodedata
from typing import Callable
from xml.sax.saxutils import escape

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.xpreformatted import XPreformatted

from app.core.config import Settings, get_settings
from app.reporting.schemas import ReportDocument, ReportFinding
from app.reporting.storage import stream_sha256
from app.reporting.versions import FONT_DIRECTORY, RENDERER_VERSION
from app.security.redaction import redact_secrets


_FONT_NAMES = ("RepoLensSans", "RepoLensSansBold", "Courier")
_REGISTERED = False
_SUPPORTED_CODEPOINTS: set[int] = set(range(32, 127)) | {9, 10, 13}
_BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x061C, 0x200E, 0x200F}
_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#991B1B"),
    "HIGH": colors.HexColor("#C2410C"),
    "MEDIUM": colors.HexColor("#A16207"),
    "LOW": colors.HexColor("#1D4ED8"),
    "INFO": colors.HexColor("#475569"),
}


class ReportRenderError(RuntimeError):
    pass


@dataclass(frozen=True)
class GeneratedReport:
    digest: str
    size_bytes: int
    page_count: int
    mime_type: str = "application/pdf"
    renderer_version: str = RENDERER_VERSION


def _register_fonts() -> None:
    global _REGISTERED, _SUPPORTED_CODEPOINTS
    if _REGISTERED:
        return
    regular = TTFont(_FONT_NAMES[0], str(FONT_DIRECTORY / "Vera.ttf"))
    bold = TTFont(_FONT_NAMES[1], str(FONT_DIRECTORY / "VeraBd.ttf"))
    for font in (regular, bold):
        pdfmetrics.registerFont(font)
    supported = set(getattr(regular.face, "charToGlyph", {}).keys())
    if supported:
        _SUPPORTED_CODEPOINTS = supported | {9, 10, 13}
    _REGISTERED = True


def _plain_text(value: object, *, limit: int = 8192, preserve_newlines: bool = True) -> str:
    """Redact, normalize, visibly escape controls/bidi/unsupported glyphs, and bound."""
    value_text = redact_secrets(str(value if value is not None else ""))
    normalized = unicodedata.normalize("NFC", value_text).replace("\r\n", "\n").replace("\r", "\n")
    output: list[str] = []
    output_length = 0
    for character in normalized:
        point = ord(character)
        if character == "\n" and preserve_newlines:
            replacement = character
        elif character == "\t":
            replacement = "    "
        elif point in _BIDI_CONTROLS or unicodedata.category(character) in {"Cc", "Cs"}:
            replacement = f"[U+{point:04X}]"
        elif point not in _SUPPORTED_CODEPOINTS:
            replacement = f"[U+{point:04X}]"
        else:
            replacement = character
        if output_length + len(replacement) > limit:
            output.append("… [truncated]")
            break
        output.append(replacement)
        output_length += len(replacement)
    return "".join(output)


def _paragraph(text: object, style: ParagraphStyle, *, limit: int = 8192) -> Paragraph:
    safe = escape(_plain_text(text, limit=limit)).replace("\n", "<br/>")
    return Paragraph(safe or "Not recorded.", style)


def _path_text(text: object) -> str:
    safe = _plain_text(text, limit=512, preserve_newlines=False)
    return "\n".join(textwrap.wrap(safe, width=76, break_long_words=True, break_on_hyphens=False))


def _code_text(text: object, start_line: int | None, settings: Settings) -> str:
    safe = _plain_text(text, limit=settings.REPORT_MAX_EXCERPT_CHARS)
    safe = "".join(
        character if character in "\n" or 32 <= ord(character) <= 126 else f"[U+{ord(character):04X}]"
        for character in safe
    )
    raw_lines = safe.splitlines()[: settings.REPORT_MAX_EXCERPT_LINES]
    output: list[str] = []
    first = start_line or 1
    for offset, line in enumerate(raw_lines):
        chunks = textwrap.wrap(line, width=100, replace_whitespace=False, drop_whitespace=False) or [""]
        for chunk_index, chunk in enumerate(chunks):
            prefix = f"{first + offset:>5} | " if chunk_index == 0 else "      | "
            output.append(prefix + chunk)
    if len(safe.splitlines()) > settings.REPORT_MAX_EXCERPT_LINES:
        output.append("      | … [additional lines omitted]")
    return escape("\n".join(output) or "[No source excerpt recorded]")


class _InvariantCanvas(Canvas):
    def __init__(self, *args, **kwargs):
        kwargs["invariant"] = 1
        kwargs["pageCompression"] = 1
        super().__init__(*args, **kwargs)


class ReportLabPdfRenderer:
    """Professional audit-style PDF projection with no network or executable content."""

    renderer_version = GeneratedReport.renderer_version

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        _register_fonts()
        self.styles = self._styles()

    @staticmethod
    def _styles() -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "cover_title": ParagraphStyle(
                "CoverTitle", parent=base["Title"], fontName=_FONT_NAMES[1], fontSize=28,
                leading=34, textColor=colors.HexColor("#0F172A"), alignment=TA_CENTER, spaceAfter=12,
            ),
            "cover_subtitle": ParagraphStyle(
                "CoverSubtitle", parent=base["Normal"], fontName=_FONT_NAMES[0], fontSize=12,
                leading=18, textColor=colors.HexColor("#475569"), alignment=TA_CENTER,
            ),
            "h1": ParagraphStyle(
                "ReportH1", parent=base["Heading1"], fontName=_FONT_NAMES[1], fontSize=17,
                leading=22, textColor=colors.HexColor("#0F172A"), spaceBefore=10, spaceAfter=9, keepWithNext=True,
            ),
            "h2": ParagraphStyle(
                "ReportH2", parent=base["Heading2"], fontName=_FONT_NAMES[1], fontSize=12,
                leading=16, textColor=colors.HexColor("#1E3A8A"), spaceBefore=8, spaceAfter=6, keepWithNext=True,
            ),
            "body": ParagraphStyle(
                "ReportBody", parent=base["BodyText"], fontName=_FONT_NAMES[0], fontSize=8.5,
                leading=12.5, textColor=colors.HexColor("#1F2937"), spaceAfter=5,
            ),
            "small": ParagraphStyle(
                "ReportSmall", parent=base["BodyText"], fontName=_FONT_NAMES[0], fontSize=7.2,
                leading=10, textColor=colors.HexColor("#475569"), spaceAfter=3,
            ),
            "label": ParagraphStyle(
                "ReportLabel", parent=base["BodyText"], fontName=_FONT_NAMES[1], fontSize=7.5,
                leading=10, textColor=colors.HexColor("#334155"), spaceAfter=2,
            ),
            "code": ParagraphStyle(
                "ReportCode", parent=base["Code"], fontName=_FONT_NAMES[2], fontSize=6.5,
                leading=8.5, textColor=colors.HexColor("#0F172A"), leftIndent=5, rightIndent=5,
                borderColor=colors.HexColor("#CBD5E1"), borderWidth=0.5, borderPadding=6,
                backColor=colors.HexColor("#F8FAFC"), spaceAfter=6,
            ),
        }

    def _on_page(self, canvas: Canvas, document: BaseDocTemplate, report_id: str) -> None:
        canvas.saveState()
        canvas.setTitle("RepoLens Analysis Report")
        canvas.setAuthor("RepoLens")
        canvas.setCreator(self.renderer_version)
        canvas.setFont(_FONT_NAMES[0], 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(18 * mm, 11 * mm, f"RepoLens • Report {_plain_text(report_id[:12], limit=12)}")
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Page {document.page}")
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
        canvas.restoreState()

    def _table(self, rows: list[list[object]], widths: list[float], *, header: bool = True) -> LongTable:
        table = LongTable(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        commands = [
            ("FONTNAME", (0, 0), (-1, -1), _FONT_NAMES[0]),
            ("FONTSIZE", (0, 0), (-1, -1), 7.2),
            ("LEADING", (0, 0), (-1, -1), 9.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        if header:
            commands.extend([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("FONTNAME", (0, 0), (-1, 0), _FONT_NAMES[1]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ])
        table.setStyle(TableStyle(commands))
        return table

    def _finding_story(self, finding: ReportFinding) -> list[object]:
        styles = self.styles
        severity_color = _SEVERITY_COLORS.get(finding.severity, colors.HexColor("#475569"))
        badge = Table(
            [[_plain_text(finding.severity, limit=32), _plain_text(finding.verification_verdict or "UNVERIFIED", limit=32)]],
            colWidths=[28 * mm, 42 * mm],
            hAlign="LEFT",
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), severity_color),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), _FONT_NAMES[0]),
            ("FONTNAME", (0, 0), (0, 0), _FONT_NAMES[1]),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story: list[object] = [
            _paragraph(finding.title, styles["h2"], limit=512),
            badge,
            Spacer(1, 4),
            self._table([
                [_paragraph("Finding ID", styles["label"]), _paragraph(finding.finding_id, styles["small"], limit=64)],
                [_paragraph("Category / Rule", styles["label"]), _paragraph(f"{finding.category} / {finding.rule_id or 'Not recorded'}", styles["small"], limit=512)],
                [_paragraph("Where", styles["label"]), _paragraph(", ".join(finding.affected_files) or "No source file recorded", styles["small"], limit=1024)],
                [_paragraph("Symbol", styles["label"]), _paragraph(finding.symbol or "Not recorded", styles["small"], limit=256)],
            ], [34 * mm, 142 * mm], header=False),
            Spacer(1, 5),
            _paragraph("WHAT / WHY", styles["label"]),
            _paragraph(finding.technical_explanation, styles["body"], limit=8192),
            _paragraph("POTENTIAL IMPACT", styles["label"]),
            _paragraph(finding.potential_impact, styles["body"], limit=4096),
            _paragraph("FIX", styles["label"]),
            _paragraph(finding.remediation.recommendation, styles["body"], limit=4096),
            _paragraph("VERIFY", styles["label"]),
        ]
        for step in finding.remediation.validation_steps[:10]:
            story.append(_paragraph(f"• {step}", styles["body"], limit=1024))
        story.append(_paragraph("EVIDENCE", styles["label"]))
        if not finding.evidence:
            story.append(_paragraph("No canonical evidence reference was recorded.", styles["body"]))
        for evidence in finding.evidence:
            location = f"{_path_text(evidence.file_path)}:{evidence.start_line or '?'}-{evidence.end_line or '?'}"
            story.append(_paragraph(f"{evidence.evidence_id} • {location}", styles["small"], limit=1024))
            if evidence.context:
                story.append(_paragraph(evidence.context, styles["small"], limit=2048))
            if evidence.excerpt:
                story.append(XPreformatted(_code_text(evidence.excerpt, evidence.start_line, self.settings), styles["code"]))
        story.extend([Spacer(1, 6), Table([[""]], colWidths=[176 * mm], rowHeights=[0.5], style=[("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#CBD5E1"))]), Spacer(1, 6)])
        return story

    def render(
        self,
        document: ReportDocument,
        output_path: Path,
        progress_callback: Callable[[int], None] | None = None,
    ) -> GeneratedReport:
        """Render and validate one PDF file. ``output_path`` must be a private temp path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        frame = Frame(18 * mm, 19 * mm, A4[0] - 36 * mm, A4[1] - 35 * mm, id="report-body")

        def on_page(canvas: Canvas, report: BaseDocTemplate) -> None:
            self._on_page(canvas, report, document.metadata.report_id)
            if progress_callback is not None:
                progress_callback(report.page)

        template = PageTemplate(
            id="report",
            frames=[frame],
            onPage=on_page,
        )
        pdf = BaseDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=19 * mm,
            title="RepoLens Analysis Report",
            author="RepoLens",
            creator=self.renderer_version,
            pageTemplates=[template],
        )
        styles = self.styles
        story: list[object] = [
            Spacer(1, 38 * mm),
            _paragraph("RepoLens", styles["cover_title"], limit=64),
            _paragraph("Evidence-backed Repository Analysis Report", styles["cover_subtitle"], limit=128),
            Spacer(1, 18 * mm),
            self._table([
                [_paragraph("Repository", styles["label"]), _paragraph(document.metadata.repository, styles["body"], limit=512)],
                [_paragraph("Branch / revision", styles["label"]), _paragraph(f"{document.metadata.branch or 'Not recorded'} / {document.metadata.commit_sha or 'Not recorded'}", styles["body"], limit=256)],
                [_paragraph("Analysis timestamp", styles["label"]), _paragraph(document.metadata.analysis_timestamp.isoformat() if document.metadata.analysis_timestamp else "Not recorded", styles["body"], limit=128)],
                [_paragraph("Report ID", styles["label"]), _paragraph(document.metadata.report_id, styles["body"], limit=64)],
            ], [42 * mm, 134 * mm], header=False),
            PageBreak(),
            _paragraph("1. Executive Summary", styles["h1"]),
            _paragraph(document.executive_summary.overall_result, styles["body"]),
        ]
        risk = document.executive_summary.risk
        risk_rows = [[_paragraph("Severity", styles["label"]), _paragraph("Count", styles["label"])]]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            risk_rows.append([_paragraph(severity, styles["body"]), _paragraph(risk.severity_counts.get(severity, 0), styles["body"])])
        story.extend([
            self._table(risk_rows, [80 * mm, 35 * mm]),
            Spacer(1, 6),
            _paragraph("Major risks", styles["h2"]),
        ])
        story.append(_paragraph(
            "\n".join(f"• {title}" for title in (document.executive_summary.major_risks or ["No actionable risks were ranked."])),
            styles["body"],
            limit=2048,
        ))
        story.append(_paragraph("Important limitations", styles["h2"]))
        story.append(_paragraph(
            "\n".join(f"• {limitation}" for limitation in document.executive_summary.important_limitations),
            styles["body"],
            limit=4096,
        ))

        story.extend([
            _paragraph("2. Analysis Scope & Coverage", styles["h1"]),
            self._table([
                [_paragraph("Coverage status", styles["label"]), _paragraph(document.coverage.status, styles["body"])],
                [_paragraph("Files discovered", styles["label"]), _paragraph(document.scope.files_discovered if document.scope.files_discovered is not None else "Not recorded", styles["body"])],
                [_paragraph("Files analyzed", styles["label"]), _paragraph(document.scope.files_analyzed if document.scope.files_analyzed is not None else "Not recorded", styles["body"])],
                [_paragraph("Truncated", styles["label"]), _paragraph("YES" if document.scope.truncated else "NO", styles["body"])],
                [_paragraph("Languages", styles["label"]), _paragraph(", ".join(f"{key}: {value}" for key, value in sorted(document.scope.languages.items())) or "Not recorded", styles["body"], limit=2048)],
                [_paragraph("Coverage interpretation", styles["label"]), _paragraph(document.coverage.distinction, styles["body"])],
            ], [42 * mm, 134 * mm], header=False),
            Spacer(1, 8),
        ])
        if document.coverage.analyzers:
            rows = [[_paragraph(label, styles["label"]) for label in ("Analyzer", "Status", "Findings", "Limitation")]]
            for analyzer in document.coverage.analyzers:
                rows.append([
                    _paragraph(analyzer.analyzer, styles["small"], limit=128),
                    _paragraph(analyzer.status, styles["small"], limit=32),
                    _paragraph(analyzer.findings_count, styles["small"]),
                    _paragraph(analyzer.limitation or "—", styles["small"], limit=512),
                ])
            story.append(self._table(rows, [38 * mm, 28 * mm, 22 * mm, 88 * mm]))

        story.append(_paragraph("3. Prioritized Fix Plan", styles["h1"]))
        if document.prioritized_fix_plan:
            rows = [[_paragraph(label, styles["label"]) for label in ("Rank", "Sequence", "Severity", "Finding", "Deterministic reason")]]
            for item in document.prioritized_fix_plan:
                rows.append([
                    _paragraph(item.priority_rank, styles["small"]),
                    _paragraph(item.priority_band, styles["small"], limit=32),
                    _paragraph(item.severity, styles["small"], limit=32),
                    _paragraph(item.title, styles["small"], limit=512),
                    _paragraph(item.priority_reason, styles["small"], limit=1024),
                ])
            story.append(self._table(rows, [12 * mm, 25 * mm, 20 * mm, 50 * mm, 69 * mm]))
        else:
            story.extend([
                Spacer(1, 4),
                _paragraph("No actionable findings entered the deterministic fix sequence.", styles["body"]),
            ])

        finding_map = {finding.finding_id: finding for finding in document.findings}
        section_number = 4
        for section in document.finding_sections:
            if not section.finding_ids:
                continue
            story.extend([PageBreak(), _paragraph(f"{section_number}. {section.title.title()}", styles["h1"])])
            for finding_id in section.finding_ids:
                finding = finding_map.get(finding_id)
                if finding:
                    story.extend(self._finding_story(finding))
            section_number += 1

        def reference_section(title: str, ids: list[str]) -> None:
            story.append(_paragraph(title, styles["h1"]))
            if not ids:
                story.append(_paragraph("No evidence-backed findings were classified in this section.", styles["body"]))
                return
            rows = [[_paragraph(label, styles["label"]) for label in ("Finding ID", "Severity", "Title", "Source")]]
            for finding_id in ids:
                finding = finding_map.get(finding_id)
                if finding:
                    rows.append([
                        _paragraph(finding.finding_id, styles["small"], limit=64),
                        _paragraph(finding.severity, styles["small"], limit=32),
                        _paragraph(finding.title, styles["small"], limit=512),
                        _paragraph(finding.analyzer or "Not recorded", styles["small"], limit=128),
                    ])
            story.append(self._table(rows, [42 * mm, 20 * mm, 78 * mm, 36 * mm]))

        story.append(PageBreak())
        reference_section("Security Vulnerabilities", document.security.vulnerability_finding_ids)
        reference_section("Security Inconsistencies", document.security.inconsistency_finding_ids)
        reference_section("Cross-Layer Contract Inconsistencies", document.contracts.finding_ids)
        reference_section("Architecture / Code Quality Findings", document.architecture.finding_ids)
        if document.architecture.overview:
            story.append(_paragraph("Recorded architecture overview", styles["h2"]))
            story.append(_paragraph(document.architecture.overview, styles["body"], limit=4096))

        story.append(_paragraph("Remediation Roadmap", styles["h1"]))
        for step in document.remediation_roadmap:
            story.append(_paragraph(f"Step {step.sequence} — {step.title}", styles["h2"], limit=512))
            story.append(_paragraph("Finding IDs: " + ", ".join(step.finding_ids), styles["small"], limit=4096))
            if step.dependency_ids:
                story.append(_paragraph("Dependencies: " + ", ".join(step.dependency_ids), styles["small"], limit=2048))

        story.extend([PageBreak(), _paragraph("Evidence Appendix", styles["h1"])])
        if document.appendix.evidence:
            rows = [[_paragraph(label, styles["label"]) for label in ("Evidence ID", "Finding ID", "File / range", "Analyzer")]]
            for evidence in document.appendix.evidence:
                location = f"{_path_text(evidence.file_path)}:{evidence.start_line or '?'}-{evidence.end_line or '?'}"
                rows.append([
                    _paragraph(evidence.evidence_id, styles["small"], limit=64),
                    _paragraph(evidence.finding_id, styles["small"], limit=64),
                    _paragraph(location, styles["small"], limit=1024),
                    _paragraph(evidence.analyzer or "Not recorded", styles["small"], limit=128),
                ])
            story.append(self._table(rows, [42 * mm, 42 * mm, 64 * mm, 28 * mm]))
        else:
            story.append(_paragraph("No canonical evidence references were recorded.", styles["body"]))

        story.append(_paragraph("Analysis Limitations", styles["h1"]))
        story.append(_paragraph(
            "\n".join(f"• {limitation}" for limitation in document.limitations),
            styles["body"],
            limit=8192,
        ))

        metadata = document.metadata
        story.extend([
            _paragraph("Report Metadata", styles["h1"]),
            self._table([
                [_paragraph("Report ID", styles["label"]), _paragraph(metadata.report_id, styles["small"], limit=64)],
                [_paragraph("RepoLens version", styles["label"]), _paragraph(metadata.application_version, styles["small"], limit=64)],
                [_paragraph("Analysis policy", styles["label"]), _paragraph(metadata.analysis_policy_version, styles["small"], limit=128)],
                [_paragraph("Report schema", styles["label"]), _paragraph(metadata.report_schema_version, styles["small"], limit=32)],
                [_paragraph("Renderer", styles["label"]), _paragraph(metadata.renderer_version, styles["small"], limit=128)],
                [_paragraph("Commit SHA", styles["label"]), _paragraph(metadata.commit_sha or "Not recorded", styles["small"], limit=64)],
                [_paragraph("Evidence digest", styles["label"]), _paragraph(metadata.evidence_digest, styles["small"], limit=64)],
                [_paragraph("Coverage artifact", styles["label"]), _paragraph(metadata.coverage_artifact_id or "Not recorded", styles["small"], limit=128)],
            ], [45 * mm, 131 * mm], header=False),
        ])

        try:
            pdf.build(story, canvasmaker=_InvariantCanvas)
            size = output_path.stat().st_size
            if size <= 0 or size > self.settings.REPORT_MAX_PDF_BYTES:
                raise ReportRenderError("Rendered PDF exceeded the configured output budget.")
            reader = PdfReader(str(output_path), strict=True)
            if reader.is_encrypted:
                raise ReportRenderError("Generated PDF was unexpectedly encrypted.")
            page_count = len(reader.pages)
            if page_count <= 0 or page_count > self.settings.REPORT_MAX_PDF_PAGES:
                raise ReportRenderError("Rendered PDF exceeded the configured page budget.")
            root = reader.trailer.get("/Root", {})
            if any(key in root for key in ("/OpenAction", "/AA")):
                raise ReportRenderError("Generated PDF contains a prohibited document action.")
            names = root.get("/Names") if hasattr(root, "get") else None
            if names and any(key in names for key in ("/JavaScript", "/EmbeddedFiles")):
                raise ReportRenderError("Generated PDF contains prohibited active or embedded content.")
            with output_path.open("rb") as stream:
                digest = stream_sha256(stream)
            return GeneratedReport(digest=digest, size_bytes=size, page_count=page_count)
        except Exception as exc:
            output_path.unlink(missing_ok=True)
            if isinstance(exc, ReportRenderError):
                raise
            raise ReportRenderError(f"PDF rendering failed: {type(exc).__name__}") from exc
