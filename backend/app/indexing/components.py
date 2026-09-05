"""Semantic ownership is separate from hash partitions and query-time regions."""

from collections import OrderedDict
import hashlib
import json
import posixpath


class ComponentResolver:
    def __init__(self, inventory, commit_sha):
        self.inventory = inventory
        self.root = inventory.root_tree(commit_sha)
        self.cache = OrderedDict()

    def boundary(self, path):
        directory = posixpath.dirname(path)
        if directory in self.cache:
            self.cache.move_to_end(directory)
            return self.cache[directory]
        current, inspected, result = directory, [], None
        for _ in range(32):
            for name in ("package.json", "pyproject.toml", "__init__.py"):
                candidate = posixpath.join(current, name)
                entry = self.inventory.path_entry(self.root, candidate)
                inspected.append((candidate, entry.object_id if entry else None))
                if entry and entry.kind == "blob" and entry.mode in {"100644", "100755"}:
                    result = {"root": current or ".", "boundary": candidate, "kind": "PACKAGE"}
                    break
            if result or not current:
                break
            current = posixpath.dirname(current)
        if result is None:
            result = {"root": directory or ".", "boundary": None, "kind": "DIRECTORY_FALLBACK"}
        result["component_id"] = "component:" + hashlib.sha256(json.dumps([result["kind"], result["root"]]).encode()).hexdigest()[:32]
        # Only membership/absence matters for component ownership, not manifest
        # version strings or unrelated dependencies within the same package.
        result["boundary_certificate"] = [(name, oid is not None) for name, oid in inspected]
        self.cache[directory] = result
        if len(self.cache) > 256:
            self.cache.popitem(last=False)
        return result

    def file_identity(self, path):
        result = dict(self.boundary(path))
        result["storage_partition"] = hashlib.sha256(path.encode()).hexdigest()[:2]
        result["analysis_region"] = "QUERY_SCOPED"
        return result
