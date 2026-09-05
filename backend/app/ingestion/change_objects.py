"""Changed-object discovery: equal Git trees are never opened or parsed."""

from contextlib import contextmanager
from pathlib import Path
import tempfile
import time

from app.ingestion.git_inventory import GitInventory, InventoryBound
from app.ingestion.classification import classify_file
from app.ingestion.detector import detect_language
from app.security.redaction import contains_secrets


def changed_objects(base, head, base_sha, head_sha, *, max_files=512, max_entries=20000, seconds=30):
    """Return a bounded changed-file region and a replayable unknown frontier."""
    frontier = [("", base.root_tree(base_sha), head.root_tree(head_sha))]
    changed, visited = [], 0
    deadline = time.monotonic() + seconds
    reason = None
    while frontier:
        path, left, right = frontier[-1]
        if left == right:
            frontier.pop()
            continue
        try:
            tables = []
            for inventory, oid in ((base, left), (head, right)):
                table = {}
                if oid:
                    for entry in inventory.entries(oid):
                        visited += 1
                        if visited > max_entries or time.monotonic() >= deadline:
                            raise InventoryBound("changed_tree_budget")
                        table[entry.name] = entry
                tables.append(table)
            pending_files, pending_trees = [], []
            for name in sorted(tables[0].keys() | tables[1].keys()):
                a, b = tables[0].get(name), tables[1].get(name)
                if a == b:
                    continue
                target = f"{path}/{name}" if path else name
                if (len(target.encode()) > 512 or contains_secrets(target) or
                        any(part in {".git", ".", ".."} or ":" in part for part in target.split("/"))):
                    raise InventoryBound("changed_path_out_of_scope")
                # A file/directory type transition is explicitly unresolved.
                if a and b and a.kind != b.kind:
                    raise InventoryBound("changed_object_type_transition")
                item = b or a
                if item.kind == "tree":
                    if len(target.split("/")) > 64:
                        raise InventoryBound("changed_tree_depth")
                    pending_trees.append((target, a.object_id if a else None, b.object_id if b else None))
                else:
                    pending_files.append((target, a, b))
            if len(changed) + len(pending_files) > max_files or len(frontier) + len(pending_trees) > max_files:
                raise InventoryBound("changed_file_budget")
            frontier.pop()
            changed.extend(pending_files)
            frontier.extend(reversed(pending_trees))
        except (InventoryBound, UnicodeError) as exc:
            reason = str(exc)
            break
    return changed, {"complete": not frontier, "stop_reason": reason,
        "entries_examined": visited, "changed_files": len(changed),
        "frontier": frontier, "scope": "CHANGED_OBJECTS", "rename_scope": "BOUNDED_EXACT_CONTENT"}


@contextmanager
def changed_workspaces(base_path, head_path, base_sha, head_sha, *, max_files, max_file_bytes, max_bytes):
    base, head = GitInventory(base_path), GitInventory(head_path)
    changes, coverage = changed_objects(base, head, base_sha, head_sha, max_files=max_files)
    with tempfile.TemporaryDirectory(prefix="repolens-diff-") as directory:
        roots = [Path(directory) / "base", Path(directory) / "head"]
        for root in roots:
            root.mkdir()
        consumed, skipped = 0, []
        for path, a, b in changes:
            contents = []
            try:
                for inventory, entry in ((base, a), (head, b)):
                    if entry is None:
                        contents.append(None)
                        continue
                    if entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
                        raise InventoryBound("changed_non_regular_object")
                    if not classify_file(path, language=detect_language(path), mode=entry.mode).eligible:
                        raise InventoryBound("changed_excluded_file")
                    allowance = min(max_file_bytes, max_bytes - consumed)
                    if allowance <= 0:
                        raise InventoryBound("changed_source_byte_budget")
                    payload = inventory.read_object(entry.object_id, kind="blob", max_bytes=allowance)
                    consumed += len(payload)
                    contents.append(payload)
                # Publish both sides together; a missing read is never a deletion.
                for root, content in zip(roots, contents):
                    if content is not None:
                        destination = root.joinpath(*path.split("/"))
                        if not destination.resolve().is_relative_to(root.resolve()):
                            raise InventoryBound("changed_path_out_of_scope")
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(content)
            except InventoryBound as exc:
                skipped.append({"path": path, "reason": str(exc)})
        coverage.update(source_bytes=consumed, skipped=skipped, complete=coverage["complete"] and not skipped)
        yield str(roots[0]), str(roots[1]), coverage
