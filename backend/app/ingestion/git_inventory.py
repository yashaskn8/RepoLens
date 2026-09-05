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

    def _open(self, *args: str):
        env = dict(os.environ)
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
        return subprocess.Popen(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
             "-c", "core.pager=cat", *args], cwd=self.repo_dir, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )

    @staticmethod
    def validate_oid(value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            raise InventoryBound("invalid immutable Git object identity")
        return value

    def read_object(self, oid: str, *, kind: str, max_bytes: int) -> bytes:
        self.validate_oid(oid)
        if kind not in {"blob", "tree"}:
            raise InventoryBound("unsupported Git object kind")
        process = self._open("cat-file", kind, oid)
        timer = threading.Timer(self.timeout, process.kill)
        timer.daemon = True
        timer.start()
        try:
            payload = process.stdout.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise InventoryBound("object_byte_limit")
            if process.wait(timeout=self.timeout) != 0:
                raise InventoryBound("object_unavailable_or_timeout")
            return payload
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

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
