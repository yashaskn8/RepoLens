"""Bounded literal import locations, never package execution or suffix guessing."""

import posixpath

from app.ingestion.schemas import SymbolKind


def import_paths(file, *, limit: int = 64) -> list[str]:
    paths = set()
    for symbol in file.symbols:
        if symbol.kind != SymbolKind.IMPORT:
            continue
        details = symbol.details
        if file.language == "python":
            modules = [details.get("module", "")] if details.get("is_from") else list(details.get("modules", {}).values())
            for module in modules:
                if not module or not isinstance(module, str):
                    continue
                dots = len(module) - len(module.lstrip("."))
                if dots:
                    base = posixpath.dirname(file.path)
                    for _ in range(dots - 1):
                        base = posixpath.join(base, "..")
                    base = posixpath.join(base, module[dots:].replace(".", "/"))
                else:
                    base = module.replace(".", "/")
                paths.update((base + ".py", base + "/__init__.py"))
        else:
            source = details.get("source", "")
            if isinstance(source, str) and source.startswith(("./", "../")):
                base = posixpath.join(posixpath.dirname(file.path), source)
                paths.update(base + ext for ext in ("", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"))
        if len(paths) >= limit:
            break
    normalized = {posixpath.normpath(path) for path in paths}
    return sorted(path for path in normalized if not path.startswith(("../", "/")) and "\\" not in path and len(path) <= 2048)[:limit]
