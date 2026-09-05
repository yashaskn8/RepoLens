"""Bounded passive Git object reads. No worktree programs or filters execute."""

from collections.abc import Iterator
from dataclasses import dataclass
import os
import re
import subprocess
import threading


class InventoryBound(RuntimeError):
    pass


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    object_id: str
    name: str


class GitInventory:
    def __init__(self, repo_dir: str, *, timeout: float = 20, max_record_bytes: int = 8192):
        self.repo_dir = repo_dir
        self.timeout = timeout
        self.max_record_bytes = max_record_bytes
        self._batch_process = None
        self._batch_lock = threading.Lock()

    def _open(self, *args: str, input_pipe: bool = False):
        env = dict(os.environ)
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
        return subprocess.Popen(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
             "-c", "core.pager=cat", *args], cwd=self.repo_dir, env=env,
            stdin=subprocess.PIPE if input_pipe else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )

    def _close_batch_locked(self) -> None:
        process, self._batch_process = self._batch_process, None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def close(self) -> None:
        with self._batch_lock:
            self._close_batch_locked()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def validate_oid(value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            raise InventoryBound("invalid immutable Git object identity")
        return value

    def read_object(self, oid: str, *, kind: str, max_bytes: int) -> bytes:
        self.validate_oid(oid)
        if kind not in {"blob", "tree"}:
            raise InventoryBound("unsupported Git object kind")
        with self._batch_lock:
            process = self._batch_process
            if process is None or process.poll() is not None:
                self._close_batch_locked()
                process = self._open("cat-file", "--batch", input_pipe=True)
                self._batch_process = process
            timer = threading.Timer(self.timeout, process.kill)
            timer.daemon = True
            timer.start()
            try:
                process.stdin.write((oid + "\n").encode("ascii"))
                process.stdin.flush()
                header = process.stdout.readline(256)
                if not header.endswith(b"\n"):
                    raise InventoryBound("object_unavailable_or_timeout")
                fields = header.rstrip(b"\n").split(b" ")
                if len(fields) != 3:
                    raise InventoryBound("object_unavailable_or_timeout")
                returned_oid, returned_kind, raw_size = fields
                try:
                    object_size = int(raw_size)
                except ValueError as exc:
                    raise InventoryBound("object_unavailable_or_timeout") from exc
                if (returned_oid.decode("ascii") != oid or returned_kind.decode("ascii") != kind
                        or object_size < 0):
                    raise InventoryBound("object_identity_mismatch")
                if object_size > max_bytes:
                    raise InventoryBound("object_byte_limit")
                payload = process.stdout.read(object_size)
                delimiter = process.stdout.read(1)
                if len(payload) != object_size or delimiter != b"\n":
                    raise InventoryBound("object_unavailable_or_timeout")
                return payload
            except (InventoryBound, OSError, UnicodeError):
                self._close_batch_locked()
                raise
            finally:
                timer.cancel()

    def root_tree(self, commit_sha: str) -> str:
        self.validate_oid(commit_sha)
        process = self._open("rev-parse", "--verify", commit_sha + "^{tree}")
        try:
            out, _ = process.communicate(timeout=self.timeout)
            if process.returncode or len(out) > 128:
                raise InventoryBound("immutable_root_unavailable")
            return self.validate_oid(out.decode("ascii").strip())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def path_entry(self, tree_oid: str, path: str) -> TreeEntry | None:
        """Exact immutable lookup; no wildcard expansion or working-tree reads."""
        self.validate_oid(tree_oid)
        if not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")) or "\\" in path or "\x00" in path:
            raise InventoryBound("unsupported_path_identity")
        process = self._open("--literal-pathspecs", "ls-tree", "-z", tree_oid, "--", path)
        timer = threading.Timer(self.timeout, process.kill)
        timer.daemon = True
        timer.start()
        try:
            result = process.stdout.read(self.max_record_bytes + 1)
            if len(result) > self.max_record_bytes or process.wait(timeout=self.timeout) != 0:
                raise InventoryBound("path_lookup_incomplete")
            if not result:
                return None
            records = result.split(b"\0")
            if len(records) != 2 or records[-1]:
                raise InventoryBound("ambiguous_path_lookup")
            header, name = records[0].split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            if name.decode("utf-8") != path:
                raise InventoryBound("path_lookup_mismatch")
            return TreeEntry(mode, kind, self.validate_oid(oid), path)
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

    def entries(self, tree_oid: str) -> Iterator[TreeEntry]:
        self.validate_oid(tree_oid)
        process = self._open("ls-tree", "-z", tree_oid)
        timer = None
        pending = bytearray()
        try:
            while True:
                # Extraction can take time between yields; only Git I/O owns
                # this timeout. The index has a separate whole-stage deadline.
                timer = threading.Timer(self.timeout, process.kill)
                timer.daemon = True
                timer.start()
                block = process.stdout.read(4096)
                timer.cancel()
                if not block:
                    break
                pending.extend(block)
                while (end := pending.find(b"\0")) >= 0:
                    record = bytes(pending[:end])
                    del pending[:end + 1]
                    if len(record) > self.max_record_bytes:
                        raise InventoryBound("inventory_record_limit")
                    header, raw_name = record.split(b"\t", 1)
                    mode, kind, oid = header.decode("ascii").split(" ")
                    name = raw_name.decode("utf-8", errors="strict")
                    if not name or name in {".", ".."} or any(c in name for c in "/\\\x00") or len(name) > 1024:
                        raise InventoryBound("unsupported_path_identity")
                    yield TreeEntry(mode, kind, self.validate_oid(oid), name)
                if len(pending) > self.max_record_bytes:
                    raise InventoryBound("inventory_record_limit")
            if pending or process.wait(timeout=self.timeout) != 0:
                raise InventoryBound("inventory_incomplete_or_timeout")
        finally:
            if timer is not None:
                timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
