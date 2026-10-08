"""Safe GitHub repository cloning and URL validation."""

import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Optional, Tuple
from urllib.parse import urlparse
from app.core.config import get_settings


class IngestionError(Exception):
    """Base exception for ingestion failures."""
    pass


class InvalidRepositoryURLError(IngestionError):
    """Raised when repository URL does not match strict GitHub HTTPS format."""
    pass


class CloneTimeoutError(IngestionError):
    """Raised when git clone exceeds configured time limit."""
    pass


class CloneFailedError(IngestionError):
    """Raised when git clone terminates with a non-zero exit code."""
    pass


class RepositoryResourceLimitError(IngestionError):
    """Raised when Git tree metadata or source blob sizes exceed admission limits."""
    pass


# Strict regex for public GitHub repository: https://github.com/owner/repo(.git)?
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)

_GIT_TRANSPORT_ENV = frozenset({
    "PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR",
    "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
})


def safe_git_environment() -> dict[str, str]:
    """Build a minimal Git transport environment without ambient Git config/secrets.

    System/global Git configuration can register arbitrary clean/smudge filters;
    repository-controlled ``.gitattributes`` can name those filters during
    checkout. Disable that configuration and Git LFS smudging, while preserving
    only platform, proxy, and CA settings needed for HTTPS transport.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in _GIT_TRANSPORT_ENV
    }
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    return env


_MAX_GIT_PATH_BYTES = 4096
_GIT_PIPE_READ_BYTES = 64 * 1024
_MAX_GIT_DIAGNOSTIC_BYTES = 64 * 1024
_GIT_OBJECT_MONITOR_INTERVAL_SECONDS = 0.02


def _resume_windows_suspended_process(process_id: int) -> None:
    """Resume a CREATE_SUSPENDED process after it has been assigned to its job."""
    import ctypes
    from ctypes import wintypes

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if not snapshot or int(snapshot) == -1:
        raise RepositoryResourceLimitError("Suspended Git process thread could not be located")
    resumed = 0
    entry = ThreadEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        found = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if int(entry.th32OwnerProcessID) == process_id:
                thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                if not thread:
                    raise RepositoryResourceLimitError("Suspended Git process thread could not be opened")
                try:
                    previous_suspend_count = kernel32.ResumeThread(thread)
                    if previous_suspend_count != 1:
                        raise RepositoryResourceLimitError("Suspended Git process state was unexpected")
                    resumed += 1
                finally:
                    kernel32.CloseHandle(thread)
            entry.dwSize = ctypes.sizeof(entry)
            found = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    if resumed != 1:
        raise RepositoryResourceLimitError("Git process did not have exactly one suspended startup thread")


class _GitProcessTreeGuard:
    """Own Git and all descendants so cancellation cannot orphan transport helpers."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self._kernel32 = None
        self._job_handle = None

    def start(self, command: list[str], **kwargs) -> subprocess.Popen:
        if self.process is not None:
            raise RuntimeError("Git process guard can only start one process")
        if os.name != "nt":
            self.process = subprocess.Popen(command, start_new_session=True, **kwargs)
            return self.process

        import ctypes
        from ctypes import wintypes

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.INT,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.INT,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            raise RepositoryResourceLimitError("Git process resource boundary could not be established")
        self._kernel32 = kernel32
        self._job_handle = job_handle

        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job_handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):  # JobObjectExtendedLimitInformation
            self.close()
            raise RepositoryResourceLimitError("Git process resource boundary could not be established")

        flags = int(kwargs.pop("creationflags", 0))
        kwargs["creationflags"] = flags | 0x00000004 | 0x00000200  # suspended + new process group
        try:
            process = subprocess.Popen(command, **kwargs)
        except Exception:
            self.close()
            raise
        self.process = process

        assigned = kernel32.AssignProcessToJobObject(job_handle, wintypes.HANDLE(int(process._handle)))
        if not assigned:
            try:
                process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.close()
                raise RepositoryResourceLimitError(
                    "Suspended Git process could not be safely terminated"
                ) from exc
            self.close()
            raise RepositoryResourceLimitError("Git process could not be assigned to its resource boundary")
        try:
            _resume_windows_suspended_process(process.pid)
        except BaseException:
            try:
                self.terminate()
            finally:
                self.close()
            raise
        return process

    def _active_windows_processes(self) -> int:
        import ctypes
        from ctypes import wintypes

        class BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        if self._job_handle is None or self._kernel32 is None:
            return 0
        info = BasicAccountingInformation()
        if not self._kernel32.QueryInformationJobObject(
            self._job_handle,
            1,  # JobObjectBasicAccountingInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        ):
            raise RepositoryResourceLimitError("Git process boundary state could not be verified")
        return int(info.ActiveProcesses)

    def terminate(self) -> None:
        if self.process is None:
            return
        if os.name == "nt":
            if self._job_handle is None or self._kernel32 is None:
                raise RepositoryResourceLimitError("Git process tree is not protected by a resource boundary")
            if not self._kernel32.TerminateJobObject(self._job_handle, 1):
                raise RepositoryResourceLimitError("Git process tree could not be safely terminated")
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                raise RepositoryResourceLimitError("Git process tree termination timed out") from exc
            deadline = time.monotonic() + 5
            while self._active_windows_processes() and time.monotonic() < deadline:
                time.sleep(0.01)
            if self._active_windows_processes():
                raise RepositoryResourceLimitError("Git process tree termination could not be confirmed")
            return

        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            if self.process.poll() is None:
                self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired as wait_exc:
                raise RepositoryResourceLimitError(
                    "Git process tree termination timed out"
                ) from wait_exc
            raise RepositoryResourceLimitError("Git process tree could not be safely terminated") from exc
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise RepositoryResourceLimitError("Git process tree termination timed out") from exc

    def close(self) -> None:
        process = self.process
        if process is None:
            if self._job_handle is not None and self._kernel32 is not None:
                self._kernel32.CloseHandle(self._job_handle)
                self._job_handle = None
            return

        try:
            if os.name == "nt":
                if self._job_handle is not None and self._active_windows_processes():
                    self.terminate()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if process.poll() is None:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired as exc:
                        raise RepositoryResourceLimitError(
                            "Git process tree termination timed out"
                        ) from exc
        finally:
            if self._job_handle is not None and self._kernel32 is not None:
                self._kernel32.CloseHandle(self._job_handle)
                self._job_handle = None
            self.process = None


def _git_object_store_bytes(repository_dir: str) -> int:
    """Return bounded local Git object-store size without following links."""
    object_dir = os.path.join(repository_dir, ".git", "objects")
    if os.path.islink(object_dir):
        raise RepositoryResourceLimitError("Git object store must not be a symbolic link")
    if not os.path.isdir(object_dir):
        return 0

    total = 0
    pending = [object_dir]
    while pending:
        current = pending.pop()
        try:
            entries = os.scandir(current)
        except OSError as exc:
            raise RepositoryResourceLimitError("Git object-store metadata could not be inspected safely") from exc
        with entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                except OSError as exc:
                    raise RepositoryResourceLimitError("Git object-store metadata could not be inspected safely") from exc
    return total


def _run_clone_with_object_budget(
    command: list[str],
    *,
    environment: dict[str, str],
    repository_dir: str,
    cwd: Optional[str] = None,
    timeout_seconds: int,
    max_git_object_bytes: int,
) -> subprocess.CompletedProcess:
    """Run Git while bounding its on-disk object footprint and captured diagnostics."""
    process_tree = _GitProcessTreeGuard()
    process = process_tree.start(
        command,
        cwd=cwd,
        env=environment,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    stderr = bytearray()
    reader: Optional[threading.Thread] = None
    reader_started = False

    def drain_stderr() -> None:
        assert process.stderr is not None
        try:
            while True:
                chunk = process.stderr.read(_GIT_PIPE_READ_BYTES)
                if not chunk:
                    return
                remaining = _MAX_GIT_DIAGNOSTIC_BYTES - len(stderr)
                if remaining > 0:
                    stderr.extend(chunk[:remaining])
        finally:
            process.stderr.close()

    reader = threading.Thread(target=drain_stderr, daemon=True)
    deadline = time.monotonic() + timeout_seconds
    try:
        reader.start()
        reader_started = True
        while process.poll() is None:
            if _git_object_store_bytes(repository_dir) > max_git_object_bytes:
                process_tree.terminate()
                raise RepositoryResourceLimitError(
                    "Git acquisition exceeded the configured object-store byte limit"
                )
            if time.monotonic() >= deadline:
                process_tree.terminate()
                raise CloneTimeoutError(f"git clone timed out after {timeout_seconds} seconds.")
            time.sleep(_GIT_OBJECT_MONITOR_INTERVAL_SECONDS)
    finally:
        try:
            if process.poll() is None:
                process_tree.terminate()
        finally:
            try:
                process_tree.close()
            finally:
                if reader_started:
                    reader.join(timeout=2)
                elif process.stderr is not None:
                    process.stderr.close()

    # Catch a final packfile write that completed between monitor intervals.
    # The monitor is reactive; this post-exit check closes the fast-process gap.
    if _git_object_store_bytes(repository_dir) > max_git_object_bytes:
        raise RepositoryResourceLimitError(
            "Git acquisition exceeded the configured object-store byte limit"
        )

    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout="",
        stderr=bytes(stderr).decode("utf-8", errors="replace"),
    )


def validate_repository_tree_budget(
    repository_dir: str,
    commit_ref: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
    max_git_object_bytes: Optional[int] = None,
    timeout_seconds: int = 30,
) -> tuple[int, int]:
    """Inspect a commit tree before checkout and reject over-budget blob sets.

    Partial clone leaves source blobs unmaterialized until checkout. This
    bounded `ls-tree` pass admits the exact tree only when file-count, per-blob,
    aggregate bytes, and metadata output fit ingestion policy.
    """
    metadata_limit = max(64 * 1024, max_files * (_MAX_GIT_PATH_BYTES + 128))
    if max_git_object_bytes is None:
        max_git_object_bytes = int(get_settings().MAX_GIT_OBJECT_BYTES)
    if _git_object_store_bytes(repository_dir) > max_git_object_bytes:
        raise RepositoryResourceLimitError("Git object-store exceeds its configured byte limit")
    command = ["git", "-c", "core.symlinks=false", "-c", "core.autocrlf=false", "ls-tree", "-r", "-l", "-z", commit_ref]
    process_tree = _GitProcessTreeGuard()
    process = process_tree.start(
        command,
        cwd=repository_dir,
        env=safe_git_environment(),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    overflow = threading.Event()
    captured = {"stdout": bytearray(), "stderr": bytearray()}

    def drain(name: str, stream, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(_GIT_PIPE_READ_BYTES)
                if not chunk:
                    return
                remaining = limit - len(captured[name])
                captured[name].extend(chunk[:max(remaining, 0)])
                if len(chunk) > remaining:
                    overflow.set()
                    return
        finally:
            stream.close()

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=drain, args=("stdout", process.stdout, metadata_limit), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr, 64 * 1024), daemon=True),
    )
    started_readers: list[threading.Thread] = []
    deadline = time.monotonic() + timeout_seconds
    limit_error: Optional[str] = None
    try:
        for reader in readers:
            reader.start()
            started_readers.append(reader)
        while process.poll() is None:
            if overflow.is_set():
                limit_error = "Git tree metadata exceeded its configured byte limit"
                process_tree.terminate()
                break
            try:
                if _git_object_store_bytes(repository_dir) > max_git_object_bytes:
                    limit_error = "Git tree inspection exceeded the configured object-store byte limit"
                    process_tree.terminate()
                    break
            except RepositoryResourceLimitError:
                limit_error = "Git tree inspection could not safely inspect the object store"
                process_tree.terminate()
                break
            if time.monotonic() >= deadline:
                limit_error = "Git tree inspection exceeded its time limit"
                process_tree.terminate()
                break
            time.sleep(_GIT_OBJECT_MONITOR_INTERVAL_SECONDS)
        process.wait()
    finally:
        try:
            if process.poll() is None:
                process_tree.terminate()
        finally:
            try:
                process_tree.close()
            finally:
                for reader in started_readers:
                    reader.join(timeout=2)
                for stream in (process.stdout, process.stderr)[len(started_readers):]:
                    if stream is not None:
                        stream.close()

    try:
        if _git_object_store_bytes(repository_dir) > max_git_object_bytes:
            limit_error = limit_error or "Git tree inspection exceeded the configured object-store byte limit"
    except RepositoryResourceLimitError:
        limit_error = limit_error or "Git tree inspection could not safely inspect the object store"

    if overflow.is_set():
        raise RepositoryResourceLimitError("Git tree metadata exceeded its configured byte limit")
    if limit_error:
        raise RepositoryResourceLimitError(limit_error)
    if process.returncode != 0:
        raise CloneFailedError("Git tree inspection failed for the requested commit")

    output = bytes(captured["stdout"])
    if output and not output.endswith(b"\0"):
        raise CloneFailedError("Git tree inspection returned malformed output")
    file_count = 0
    total_bytes = 0
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_type, _object_id, size_raw = metadata.split(b" ", 3)
        except ValueError as exc:
            raise CloneFailedError("Git tree inspection returned malformed output") from exc
        if len(path) > _MAX_GIT_PATH_BYTES:
            raise RepositoryResourceLimitError("Repository path exceeds the acquisition path limit")
        if object_type == b"commit":
            continue  # submodule gitlinks are not recursively materialized
        if object_type != b"blob":
            raise CloneFailedError("Git tree inspection returned an unexpected object type")
        try:
            blob_size = int(size_raw)
        except ValueError as exc:
            raise CloneFailedError("Git tree inspection omitted a blob size") from exc
        file_count += 1
        total_bytes += blob_size
        if file_count > max_files:
            raise RepositoryResourceLimitError("Repository exceeds the configured file-count limit")
        if blob_size > max_file_bytes:
            raise RepositoryResourceLimitError("Repository contains a blob exceeding the configured per-file limit")
        if total_bytes > max_total_bytes:
            raise RepositoryResourceLimitError("Repository exceeds the configured aggregate source-byte limit")
    return file_count, total_bytes


def validate_github_url(url: str) -> str:
    """Validate that URL is strictly a public HTTPS github.com repository URL.
    
    Rejects non-HTTPS schemes, other hosts, embedded credentials, shell characters, and invalid paths.
    Returns normalized URL format: https://github.com/{owner}/{repo}.git
    """
    if not url or not isinstance(url, str):
        raise InvalidRepositoryURLError("Repository URL must be a non-empty string.")

    cleaned_url = url.strip()

    # Disallow shell metacharacters, control chars, whitespace, or flags
    if re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_url):
        raise InvalidRepositoryURLError("Repository URL contains forbidden characters.")

    # Disallow flags attempting to inject git options
    if cleaned_url.startswith("-"):
        raise InvalidRepositoryURLError("Repository URL cannot start with a dash.")

    parsed = urlparse(cleaned_url)

    # Must be HTTPS
    if parsed.scheme.lower() != "https":
        raise InvalidRepositoryURLError(f"Only HTTPS protocol is permitted; got '{parsed.scheme}'.")

    # Disallow embedded credentials (e.g. https://user:pass@github.com)
    if parsed.username or parsed.password:
        raise InvalidRepositoryURLError("Credentials in repository URLs are strictly prohibited.")

    # Must be github.com
    if parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise InvalidRepositoryURLError(f"Only github.com repositories are supported; got '{parsed.netloc}'.")

    match = GITHUB_URL_PATTERN.match(cleaned_url)
    if not match:
        raise InvalidRepositoryURLError(
            "Invalid GitHub repository URL format. Expected 'https://github.com/owner/repo'."
        )

    owner, repo = match.groups()
    if owner in (".", "..") or repo in (".", ".."):
        raise InvalidRepositoryURLError("Invalid owner or repository name.")

    # Remove trailing .git if present in repo group
    if repo.endswith(".git"):
        repo = repo[:-4]

    return f"https://github.com/{owner}/{repo}.git"


def clone_repository(
    repo_url: str,
    branch: Optional[str] = None,
    target_dir: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> Tuple[str, str]:
    """Safely perform a shallow clone of a public GitHub repository without executing code.
    
    Returns:
        Tuple of (workspace_path, commit_sha)
    """
    settings = get_settings()
    timeout = timeout_seconds or settings.CLONE_TIMEOUT_SECONDS
    normalized_url = validate_github_url(repo_url)

    dest_dir = target_dir or tempfile.mkdtemp(prefix="repolens_repo_")

    cmd = [
        "git",
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--no-tags",
        "--filter=blob:none",
        "--no-checkout",
        "--no-recurse-submodules",
        "--config",
        "core.symlinks=false",
        # Evidence manifests are bound to Git blob bytes. Prevent checkout-time
        # newline conversion from making the worktree differ from that source.
        "--config",
        "core.autocrlf=false",
        "--config",
        "credential.helper=",
    ]

    if branch:
        # Validate branch name doesn't start with dash or contain shell characters
        cleaned_branch = branch.strip()
        if re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_branch) or cleaned_branch.startswith("-"):
            raise IngestionError(f"Invalid branch name: '{branch}'")
        cmd.extend(["--branch", cleaned_branch, "--single-branch"])

    cmd.extend(["--", normalized_url, dest_dir])

    env = safe_git_environment()

    try:
        result = _run_clone_with_object_budget(
            cmd,
            environment=env,
            repository_dir=dest_dir,
            timeout_seconds=timeout,
            max_git_object_bytes=int(settings.MAX_GIT_OBJECT_BYTES),
        )

        if result.returncode != 0:
            # Clean up directory on failure if created by us
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git clone failed with exit code {result.returncode}: {result.stderr.strip()}")

        validate_repository_tree_budget(
            dest_dir,
            "HEAD",
            max_files=int(settings.MAX_REPO_FILES),
            max_file_bytes=int(settings.MAX_FILE_SIZE_BYTES),
            max_total_bytes=int(settings.MAX_TOTAL_SOURCE_BYTES),
            max_git_object_bytes=int(settings.MAX_GIT_OBJECT_BYTES),
            timeout_seconds=min(timeout, 60),
        )

        checkout_result = _run_clone_with_object_budget(
            ["git", "checkout", "--detach", "HEAD"],
            environment=env,
            repository_dir=dest_dir,
            cwd=dest_dir,
            timeout_seconds=timeout,
            max_git_object_bytes=int(settings.MAX_GIT_OBJECT_BYTES),
        )
        if checkout_result.returncode != 0:
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError("git checkout failed after repository admission.")

        # Record exact commit SHA
        rev_cmd = ["git", "rev-parse", "HEAD"]
        rev_result = subprocess.run(
            rev_cmd,
            cwd=dest_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if rev_result.returncode != 0:
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git rev-parse HEAD failed with exit code {rev_result.returncode}: {rev_result.stderr.strip()}")

        commit_sha = rev_result.stdout.strip()
        if not re.match(r"^[0-9a-fA-F]{40}$", commit_sha):
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git rev-parse HEAD returned invalid non-40-character commit SHA: '{commit_sha}'")

        return dest_dir, commit_sha

    except subprocess.TimeoutExpired:
        if target_dir is None and os.path.exists(dest_dir):
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise CloneTimeoutError(f"git clone timed out after {timeout} seconds.")
    except Exception as exc:
        if target_dir is None and os.path.exists(dest_dir):
            shutil.rmtree(dest_dir, ignore_errors=True)
        if isinstance(exc, IngestionError):
            raise
        raise CloneFailedError(f"Unexpected clone error: {str(exc)}")


def get_git_resolved_branch_or_ref(repo_dir: str) -> Optional[str]:
    """Deterministically inspect a local git repository to discover its current resolved branch or ref.

    Returns:
        The branch name (e.g. 'main', 'master', 'feature/x'), or ref string if detached HEAD, or None.
    """
    if not os.path.exists(repo_dir) or not os.path.exists(os.path.join(repo_dir, ".git")):
        return None

    # 1. Try symbolic-ref for active branch
    try:
        res = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    # 2. Fallback to rev-parse --abbrev-ref HEAD
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0:
            out = res.stdout.strip()
            if out and out != "HEAD":
                return out
    except Exception:
        pass

    # 3. If in detached HEAD state, return ref with commit SHA prefix
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            full_sha = res.stdout.strip()
            return f"HEAD@{full_sha[:8]}"
    except Exception:
        pass

    return None
