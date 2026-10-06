"""Transfer only the Claude Code account credential, never connected-service tokens."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pyzipper


ARCHIVE_MEMBER = "claude-auth.json"
BACKUP_NAME = ".share-claude-backup.json"
KEYCHAIN_SERVICE = "Claude Code-credentials"
BACKUP_KEYCHAIN_SERVICE = "share-claude-original-credentials"
MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024


class ShareClaudeError(Exception):
    pass


def _json_object(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ShareClaudeError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ShareClaudeError(f"{label} must be a JSON object")
    return value


def _oauth(value: object) -> dict:
    if not isinstance(value, dict):
        raise ShareClaudeError("Claude account credential is missing")
    for name in ("accessToken", "refreshToken"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise ShareClaudeError(f"Claude account credential has no {name}")
    return value


def _encode(value: dict) -> bytes:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise ShareClaudeError("Credential exceeds the size limit")
    return raw


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".share-claude-", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


class FileStore:
    def __init__(self, config_dir: Path):
        self.path = config_dir / ".credentials.json"
        self.backup_path = config_dir / BACKUP_NAME

    def read_blob(self) -> dict:
        if not self.path.exists():
            return {}
        if self.path.is_symlink():
            raise ShareClaudeError("Credential file is a symlink")
        return _json_object(self.path.read_bytes(), "Credential file")

    def write_blob(self, value: dict) -> None:
        if self.path.is_symlink():
            raise ShareClaudeError("Credential file is a symlink")
        _write_atomic(self.path, _encode(value))

    def backup_exists(self) -> bool:
        return self.backup_path.exists() or self.backup_path.is_symlink()

    def save_backup(self, oauth: dict) -> None:
        if self.backup_exists():
            raise ShareClaudeError(f"Backup already exists: {self.backup_path}")
        _write_exclusive(self.backup_path, _encode({"version": 1, "claudeAiOauth": oauth}))

    def read_backup(self) -> dict:
        if self.backup_path.is_symlink():
            raise ShareClaudeError("Backup file is a symlink")
        if not self.backup_path.exists():
            raise ShareClaudeError("No backup found")
        data = _json_object(self.backup_path.read_bytes(), "Backup")
        if data.get("version") != 1:
            raise ShareClaudeError("Unsupported backup version")
        return _oauth(data.get("claudeAiOauth"))

    def remove_backup(self) -> None:
        self.backup_path.unlink()


class KeychainStore:
    def __init__(self, config_dir: Path):
        self.backup_path = config_dir / BACKUP_NAME
        self.helper = Path(__file__).with_name("keychain.swift")
        if not shutil.which("swiftc") or not self.helper.exists():
            raise ShareClaudeError("Swift compiler is required for macOS Keychain access")

    def _helper_binary(self) -> Path:
        digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()[:16]
        cache_dir = Path("~/.cache/share-claude").expanduser()
        cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        binary = cache_dir / f"keychain-{digest}"
        if binary.exists():
            return binary
        fd, temp_name = tempfile.mkstemp(prefix="keychain-build-", dir=cache_dir)
        os.close(fd)
        temp_path = Path(temp_name)
        try:
            result = subprocess.run(
                ["swiftc", str(self.helper), "-o", str(temp_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                raise ShareClaudeError(result.stderr.strip() or "Could not compile Keychain helper")
            temp_path.chmod(0o700)
            os.replace(temp_path, binary)
        finally:
            temp_path.unlink(missing_ok=True)
        return binary

    def _call(self, operation: str, service: str, value: bytes | None = None) -> bytes | None:
        result = subprocess.run(
            [str(self._helper_binary()), operation, service],
            input=value,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if operation == "read" and result.returncode == 3:
            return None
        if result.returncode:
            message = result.stderr.decode(errors="replace").strip()
            raise ShareClaudeError(message or "macOS Keychain operation failed")
        return result.stdout

    def read_blob(self) -> dict:
        raw = self._call("read", KEYCHAIN_SERVICE)
        return _json_object(raw, "Keychain credential") if raw is not None else {}

    def write_blob(self, value: dict) -> None:
        self._call("write", KEYCHAIN_SERVICE, _encode(value))

    def backup_exists(self) -> bool:
        return self.backup_path.exists() or self._call("read", BACKUP_KEYCHAIN_SERVICE) is not None

    def save_backup(self, oauth: dict) -> None:
        if self.backup_exists():
            raise ShareClaudeError("A Claude credential backup already exists")
        self._call("write", BACKUP_KEYCHAIN_SERVICE, _encode({"version": 1, "claudeAiOauth": oauth}))
        try:
            _write_exclusive(self.backup_path, b'{"backend":"macOS Keychain"}\n')
        except BaseException:
            self._call("delete", BACKUP_KEYCHAIN_SERVICE)
            raise

    def read_backup(self) -> dict:
        raw = self._call("read", BACKUP_KEYCHAIN_SERVICE)
        if raw is None:
            raise ShareClaudeError("No Keychain backup found")
        data = _json_object(raw, "Keychain backup")
        if data.get("version") != 1:
            raise ShareClaudeError("Unsupported backup version")
        return _oauth(data.get("claudeAiOauth"))

    def remove_backup(self) -> None:
        self._call("delete", BACKUP_KEYCHAIN_SERVICE)
        self.backup_path.unlink(missing_ok=True)


def _store():
    config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")).expanduser().resolve()
    if sys.platform == "linux":
        return FileStore(config_dir)
    if sys.platform != "darwin":
        raise ShareClaudeError("Supported platforms are macOS and Linux")
    if config_dir != Path("~/.claude").expanduser().resolve():
        raise ShareClaudeError("Custom CLAUDE_CONFIG_DIR is not supported on macOS")
    keychain = KeychainStore(config_dir)
    if keychain.read_blob().get("claudeAiOauth") is not None:
        return keychain
    file_store = FileStore(config_dir)
    if file_store.read_blob().get("claudeAiOauth") is not None:
        return file_store
    return keychain


def _read_archive(path: Path, password: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ShareClaudeError("Archive must be a regular file")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ShareClaudeError("Archive exceeds the size limit")
    try:
        with pyzipper.AESZipFile(path, "r") as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].filename != ARCHIVE_MEMBER:
                raise ShareClaudeError("Archive has an unexpected format")
            if members[0].file_size > MAX_CREDENTIAL_BYTES:
                raise ShareClaudeError("Credential exceeds the size limit")
            archive.setpassword(password.encode())
            with archive.open(members[0]) as stream:
                raw = stream.read(MAX_CREDENTIAL_BYTES + 1)
            if len(raw) > MAX_CREDENTIAL_BYTES:
                raise ShareClaudeError("Credential exceeds the size limit")
    except (OSError, ValueError, RuntimeError, pyzipper.BadZipFile) as exc:
        raise ShareClaudeError("Could not open archive; check the file and passcode") from exc
    data = _json_object(raw, "Archive credential")
    if data.get("version") != 1:
        raise ShareClaudeError("Unsupported archive version")
    return _oauth(data.get("claudeAiOauth"))


def _write_archive(path: Path, oauth: dict, password: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".share-claude-", suffix=".zip", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with pyzipper.AESZipFile(
            temp_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as archive:
            archive.setpassword(password.encode())
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            archive.writestr(ARCHIVE_MEMBER, _encode({"version": 1, "claudeAiOauth": oauth}))
        os.link(temp_path, path)
    except FileExistsError as exc:
        raise ShareClaudeError(f"Output already exists: {path}") from exc
    finally:
        temp_path.unlink(missing_ok=True)


def _status_logged_in() -> bool:
    if not shutil.which("claude"):
        return False
    result = subprocess.run(["claude", "auth", "status"], capture_output=True, text=True, check=False)
    try:
        return json.loads(result.stdout).get("loggedIn") is True
    except (ValueError, AttributeError):
        raise ShareClaudeError("Could not determine Claude login status") from None


def _reject_environment_auth() -> None:
    names = (
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    )
    if any(os.environ.get(name) for name in names):
        raise ShareClaudeError("Unset environment-based Claude authentication before use or restore")


def _share(output: Path) -> None:
    oauth = _oauth(_store().read_blob().get("claudeAiOauth"))
    password = getpass.getpass("Archive passcode (at least 16 characters): ")
    if len(password) < 16:
        raise ShareClaudeError("Passcode must have at least 16 characters")
    if password != getpass.getpass("Confirm passcode: "):
        raise ShareClaudeError("Passcodes do not match")
    _write_archive(output, oauth, password)
    print(f"Created {output}")


def _use(archive_path: Path) -> None:
    _reject_environment_auth()
    password = getpass.getpass("Archive passcode: ")
    oauth = _read_archive(archive_path, password)
    store = _store()
    if store.backup_exists():
        raise ShareClaudeError("A backup already exists; run restore before importing another credential")
    current = store.read_blob()
    old_oauth = current.get("claudeAiOauth")
    logged_in = _status_logged_in()
    if logged_in or old_oauth is not None:
        answer = input("Replace the current Claude login? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled")
            return
        if old_oauth is None:
            raise ShareClaudeError("Claude reports a login, but no stored credential was found")
        store.save_backup(_oauth(old_oauth))
    current["claudeAiOauth"] = oauth
    store.write_blob(current)
    print("Claude credential imported" + ("; original saved for restore" if old_oauth else ""))


def _restore() -> None:
    _reject_environment_auth()
    store = _store()
    original = store.read_backup()
    current = store.read_blob()
    current["claudeAiOauth"] = original
    store.write_blob(current)
    store.remove_backup()
    print("Original Claude credential restored; backup removed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="share-claude")
    commands = parser.add_subparsers(dest="command", required=True)
    share = commands.add_parser("share", help="Create an AES-256 encrypted ZIP")
    share.add_argument(
        "-o", "--output", type=Path,
        default=Path(f"claude-auth-{datetime.now():%Y%m%d-%H%M%S}.zip"),
    )
    use = commands.add_parser("use", help="Import a credential from an encrypted ZIP")
    use.add_argument("archive", type=Path)
    commands.add_parser("restore", help="Restore the previous local credential")
    args = parser.parse_args(argv)
    try:
        if args.command == "share":
            _share(args.output)
        elif args.command == "use":
            _use(args.archive)
        else:
            _restore()
    except (ShareClaudeError, OSError, EOFError) as exc:
        print(f"share-claude: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
