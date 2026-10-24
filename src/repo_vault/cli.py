
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

CONFIG_DIR = ".repo-vault"
RECIPIENTS_FILE = "recipients.txt"
SECRETS_DIR = "secrets"


class VaultError(Exception):
    """Expected command error shown without a traceback."""


def git_root() -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise VaultError("Run repo-vault from inside a Git repository.") from exc
    return Path(result.stdout.strip()).resolve()


def config_paths(root: Path) -> tuple[Path, Path, Path]:
    config_dir = root / CONFIG_DIR
    return config_dir, config_dir / RECIPIENTS_FILE, config_dir / SECRETS_DIR


def require_age() -> str:
    executable = shutil.which("age")
    if executable is None:
        raise VaultError(
            "The age command was not found. Install age from "
            "https://github.com/FiloSottile/age and try again."
        )
    return executable


def validate_recipient(recipient: str) -> str:
    value = recipient.strip()
    if not value.startswith("age1"):
        raise VaultError("This version accepts age X25519 public keys beginning with age1.")
    return value


def initialize(root: Path, recipient: str) -> None:
    value = validate_recipient(recipient)
    config_dir, recipients_path, secrets_dir = config_paths(root)
    if recipients_path.exists():
        raise VaultError(f"{recipients_path.relative_to(root)} already exists.")
    config_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    recipients_path.write_text(value + "\n", encoding="utf-8")
    recipients_path.chmod(0o644)
    secrets_dir.mkdir(mode=0o755, exist_ok=True)
    print(f"Initialized {config_dir.relative_to(root)}")


def add_recipient(root: Path, recipient: str) -> None:
    _, recipients_path, _ = config_paths(root)
    if not recipients_path.is_file():
        raise VaultError("No recipient list found. Run repo-vault init first.")
    value = validate_recipient(recipient)
    recipients = [
        line.strip()
        for line in recipients_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if value in recipients:
        print("Recipient is already listed.")
        return
    with recipients_path.open("a", encoding="utf-8") as recipient_file:
        recipient_file.write(value + "\n")
    print("Added recipient. Re-encrypt existing secrets to include this recipient.")


def list_recipients(root: Path) -> None:
    _, recipients_path, _ = config_paths(root)
    if not recipients_path.is_file():
        raise VaultError("No recipient list found. Run repo-vault init first.")
    recipients = [
        line.strip()
        for line in recipients_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not recipients:
        print("No recipients configured.")
        return
    for recipient in recipients:
        print(recipient)


def source_path(root: Path, value: str) -> tuple[Path, str]:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    try:
        relative_path = path.relative_to(root)
    except ValueError as exc:
        raise VaultError("The file to encrypt must be inside this Git repository.") from exc
    if not path.is_file():
        raise VaultError(f"Not a regular file: {value}")
    if CONFIG_DIR in relative_path.parts:
        raise VaultError("Files inside .repo-vault cannot be encryption inputs.")
    return path, relative_path.as_posix()


def ensure_ignored_and_untracked(root: Path, relative_path: str) -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative_path],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if tracked.returncode == 0:
        raise VaultError(
            f"{relative_path} is already tracked by Git. Stop tracking it and handle "
            "existing copies before encrypting it."
        )
    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", "--", relative_path],
        cwd=root,
    )
    if ignored.returncode != 0:
        raise VaultError(f"Add {relative_path} to .gitignore before encrypting it.")


def encrypt(root: Path, source_value: str) -> None:
    age = require_age()
    _, recipients_path, secrets_dir = config_paths(root)
    if not recipients_path.is_file():
        raise VaultError("No recipient list found. Run repo-vault init first.")
    source, relative_path = source_path(root, source_value)
    ensure_ignored_and_untracked(root, relative_path)
    recipients = [
        line.strip()
        for line in recipients_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not recipients:
        raise VaultError("The recipient list is empty.")
    destination = secrets_dir / f"{relative_path}.age"
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if destination.exists():
        raise VaultError(f"{destination.relative_to(root)} already exists; move it aside first.")
    result = subprocess.run(
        [age, "-R", str(recipients_path), "-o", str(destination), str(source)],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        destination.unlink(missing_ok=True)
        raise VaultError("age could not encrypt the file; no ciphertext was kept.")
    print(f"Encrypted to {destination.relative_to(root)}")
    print("The plaintext was left in place. Keep it ignored and do not commit it.")


def decrypt(root: Path, encrypted_value: str, identity_value: str, output_value: str) -> None:
    age = require_age()
    encrypted = Path(encrypted_value).expanduser()
    if not encrypted.is_absolute():
        encrypted = Path.cwd() / encrypted
    encrypted = encrypted.resolve()
    if not encrypted.is_file():
        raise VaultError(f"Encrypted file not found: {encrypted_value}")
    identity = Path(identity_value).expanduser()
    if not identity.is_absolute():
        identity = Path.cwd() / identity
    identity = identity.resolve()
    if not identity.is_file():
        raise VaultError(f"Identity file not found: {identity_value}")
    try:
        identity.relative_to(root)
    except ValueError:
        pass
    else:
        raise VaultError("Keep your private age identity outside the Git repository.")
    output = Path(output_value).expanduser()
    if not output.is_absolute():
        output = Path.cwd() / output
    output = output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise VaultError("Choose an output path outside the Git repository.")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise VaultError(f"Output already exists; refusing to overwrite: {output}") from exc
    os.close(fd)
    result = subprocess.run(
        [age, "--decrypt", "--identity", str(identity), "--output", str(output), str(encrypted)],
        check=False,
    )
    if result.returncode != 0:
        output.unlink(missing_ok=True)
        raise VaultError("age could not decrypt the file; no plaintext was kept.")
    try:
        output.chmod(0o600)
    except OSError:
        pass
    print(f"Decrypted to {output}")
    print("Keep this plaintext file private and remove it when it is no longer needed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-vault",
        description="Store age-encrypted files in Git without storing plaintext there.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init", help="create the recipient list")
    init_parser.add_argument("--recipient", required=True, help="age public key")
    recipient_parser = commands.add_parser("add-recipient", help="add an age public key")
    recipient_parser.add_argument("recipient", help="age public key")
    commands.add_parser("recipients", help="list configured public keys")
    encrypt_parser = commands.add_parser("encrypt", help="encrypt a Git-ignored file")
    encrypt_parser.add_argument("file", help="path to a Git-ignored file in the repository")
    decrypt_parser = commands.add_parser("decrypt", help="decrypt outside the repository")
    decrypt_parser.add_argument("file", help="path to an encrypted age file")
    decrypt_parser.add_argument("--identity", required=True, help="path to your private age identity")
    decrypt_parser.add_argument("--output", required=True, help="plaintext output path outside the repository")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        root = git_root()
        if args.command == "init":
            initialize(root, args.recipient)
        elif args.command == "add-recipient":
            add_recipient(root, args.recipient)
        elif args.command == "recipients":
            list_recipients(root)
        elif args.command == "encrypt":
            encrypt(root, args.file)
        elif args.command == "decrypt":
            decrypt(root, args.file, args.identity, args.output)
    except VaultError as exc:
        print(f"repo-vault: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
