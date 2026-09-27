"""Deterministic language and framework detection based on static file evidence."""

import json
import os
import re
from typing import Dict, List, Optional
from app.ingestion.schemas import FrameworkDetected

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".md": "markdown",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".sh": "shell",
    ".bash": "shell",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c_header",
}

# Known Python packages and framework representations
PYTHON_FRAMEWORK_SIGNATURES = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "sqlalchemy": "SQLAlchemy",
    "pydantic": "Pydantic",
    "alembic": "Alembic",
    "uvicorn": "Uvicorn",
    "pytest": "Pytest",
    "celery": "Celery",
    "langchain": "LangChain",
    "langgraph": "LangGraph",
    "httpx": "HTTPX",
    "requests": "Requests",
    "torch": "PyTorch",
    "tensorflow": "TensorFlow",
}

# Known JavaScript/TypeScript packages
JS_FRAMEWORK_SIGNATURES = {
    "next": "Next.js",
    "react": "React",
    "vue": "Vue.js",
    "svelte": "Svelte",
    "express": "Express",
    "fastify": "Fastify",
    "nest": "NestJS",
    "@nestjs/core": "NestJS",
    "axios": "Axios",
    "tailwindcss": "TailwindCSS",
    "prisma": "Prisma",
    "typeorm": "TypeORM",
    "jest": "Jest",
    "vitest": "Vitest",
}


def detect_language(file_path: str) -> Optional[str]:
    """Detect source language from file extension."""
    _, ext = os.path.splitext(file_path)
    return EXTENSION_LANGUAGE_MAP.get(ext.lower())


def _bounded_manifest_bytes(
    repo_dir: str,
    filename: str,
    *,
    max_file_bytes: int,
    manifest_contents: dict[str, bytes] | None,
) -> bytes | None:
    """Return one admitted manifest payload without an unbounded file read."""
    if manifest_contents is not None:
        return manifest_contents.get(filename)
    path = os.path.join(repo_dir, filename)
    try:
        if os.stat(path).st_size > max_file_bytes:
            return None
        with open(path, "rb") as source:
            content = source.read(max_file_bytes + 1)
        if len(content) > max_file_bytes:
            return None
        return content
    except OSError:
        return None


def detect_frameworks(
    repo_dir: str,
    *,
    max_file_bytes: int = 1_048_576,
    manifest_contents: dict[str, bytes] | None = None,
) -> List[FrameworkDetected]:
    """Deterministically scan repository manifests (package.json, requirements.txt, pyproject.toml)
    to detect libraries and frameworks without executing code.
    """
    detected: List[FrameworkDetected] = []
    seen: set[str] = set()

    # 1. Check package.json
    pkg_json_bytes = _bounded_manifest_bytes(
        repo_dir,
        "package.json",
        max_file_bytes=max_file_bytes,
        manifest_contents=manifest_contents,
    )
    if pkg_json_bytes is not None:
        try:
            data = json.loads(pkg_json_bytes.decode("utf-8", errors="ignore"))
            if not isinstance(data, dict):
                data = {}
            all_deps = {}
            if isinstance(data.get("dependencies"), dict):
                all_deps.update(data["dependencies"])
            if isinstance(data.get("devDependencies"), dict):
                all_deps.update(data["devDependencies"])

            for dep_name, version in all_deps.items():
                lower_dep = dep_name.lower()
                for sig_key, framework_name in JS_FRAMEWORK_SIGNATURES.items():
                    if sig_key in lower_dep and framework_name not in seen:
                        seen.add(framework_name)
                        detected.append(
                            FrameworkDetected(
                                name=framework_name,
                                version=str(version) if version else None,
                                evidence=f"Declared '{dep_name}' in package.json",
                            )
                        )
        except (TypeError, ValueError, UnicodeError):
            pass

    # 2. Check requirements.txt
    req_txt_bytes = _bounded_manifest_bytes(
        repo_dir,
        "requirements.txt",
        max_file_bytes=max_file_bytes,
        manifest_contents=manifest_contents,
    )
    if req_txt_bytes is not None:
        try:
            lines = req_txt_bytes.decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Match package name before operators like ==, >=, <=, ~=, <, >
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[>=<~!\s]+(.*))?$", line)
                if match:
                    pkg = match.group(1).lower()
                    ver = match.group(2) if match.group(2) else None
                    for sig_key, framework_name in PYTHON_FRAMEWORK_SIGNATURES.items():
                        if sig_key == pkg and framework_name not in seen:
                            seen.add(framework_name)
                            detected.append(
                                FrameworkDetected(
                                    name=framework_name,
                                    version=ver.strip() if ver else None,
                                    evidence=f"Declared '{line}' in requirements.txt",
                                )
                            )
        except (TypeError, ValueError, UnicodeError):
            pass

    # 3. Check pyproject.toml
    pyproject_bytes = _bounded_manifest_bytes(
        repo_dir,
        "pyproject.toml",
        max_file_bytes=max_file_bytes,
        manifest_contents=manifest_contents,
    )
    if pyproject_bytes is not None:
        try:
            content = pyproject_bytes.decode("utf-8", errors="ignore")
            for sig_key, framework_name in PYTHON_FRAMEWORK_SIGNATURES.items():
                if sig_key in content.lower() and framework_name not in seen:
                    seen.add(framework_name)
                    detected.append(
                        FrameworkDetected(
                            name=framework_name,
                            version=None,
                            evidence=f"Referenced '{sig_key}' in pyproject.toml",
                        )
                    )
        except (TypeError, ValueError, UnicodeError):
            pass

    return detected
