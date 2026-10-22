#!/usr/bin/env python3
"""
Master Secrets Manager (secrets_manager.py)
===========================================
A zero-dependency, cross-platform CLI tool to discover, backup, and restore
all .env files, SSH keys, cloud credentials, and secret files into a single,
human-readable Markdown master file with embedded YAML metadata cards.

Usage:
    python3 secrets_manager.py scan
    python3 secrets_manager.py backup [--output master_secrets.md] [--scan-dir ~] [--yes]
    python3 secrets_manager.py restore [--input master_secrets.md] [--dry-run] [--yes]
"""

import os
import sys
import re
import stat
import base64
import difflib
import platform
import argparse
from pathlib import Path
from datetime import datetime

# --- ANSI Terminal Formatting ---
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

def supports_color():
    return sys.stdout.isatty() and platform.system() != "Windows" or os.environ.get("ANSICON")

def color(text, code):
    return f"{code}{text}{Style.RESET}" if supports_color() else text


# --- Scan Directories & Filters ---
EXCLUDE_DIR_NAMES = {
    "node_modules", ".git", ".svn", ".hg", "dist", "build", "out",
    ".next", ".nuxt", ".turbo", "vendor", "__pycache__", ".venv",
    "venv", "env", "myenv", ".idea", ".vscode", ".vscode-insiders",
    ".gradle", ".m2", ".pytest_cache", ".mypy_cache", ".cargo",
    ".rustup", ".pyenv", ".nvm", ".claude", "Library", "Applications",
    ".Trash", ".cache", "Caches", "AppData", "Local Settings",
    "site-packages", "dist-packages", "extensions", "third_party",
    "google-cloud-sdk"
}

TEMPLATE_SUFFIXES = (
    ".example", ".sample", ".template", ".dist", ".bak", ".old", ".backup", ".tmp"
)

CATEGORY_DOTENV = "dotenv"
CATEGORY_SSH = "ssh_key"
CATEGORY_AWS = "cloud_credentials"
CATEGORY_DOTFILE = "auth_dotfile"
CATEGORY_KEY = "private_key"
CATEGORY_RECOVERY = "recovery_codes"


def normalize_to_home(path_str):
    """Converts absolute path to ~/relative/path using forward slashes for cross-platform portability."""
    p = Path(path_str).resolve()
    try:
        rel = p.relative_to(Path.home())
        return f"~/{rel.as_posix()}"
    except ValueError:
        return p.as_posix()


def expand_from_home(path_str, base_dir=None):
    """Expands ~/path to absolute Path on the current operating system."""
    if not path_str:
        return Path.home() if not base_dir else Path(base_dir).resolve()

    if base_dir:
        if path_str == "~":
            return Path(base_dir).resolve()
        clean = path_str[2:] if path_str.startswith("~/") else path_str.lstrip("/\\")
        return (Path(base_dir) / clean).resolve()

    return Path(os.path.expanduser(path_str)).resolve()


def is_binary_file(file_path):
    """Detects if a file is binary by checking for null bytes in the first 1024 bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return False


def classify_file(path_obj):
    """
    Returns (category, is_match) for a given Path object.
    Filters out dummy templates (.env.example, etc.).
    """
    name = path_obj.name.lower()
    parent_name = path_obj.parent.name.lower()

    # Skip templates
    if any(name.endswith(suffix) for suffix in TEMPLATE_SUFFIXES):
        return None, False

    # 1. Environment files
    if name == ".env" or name.startswith(".env."):
        return CATEGORY_DOTENV, True

    # 2. SSH Keys & config (ignore known_hosts / authorized_keys)
    if parent_name == ".ssh":
        if name == "config":
            return CATEGORY_SSH, True
        if (name.startswith("id_") or name == "id") and not name.endswith(".pub"):
            return CATEGORY_SSH, True

    # 3. Cloud Credentials
    if parent_name == ".aws" and name in ("credentials", "config"):
        return CATEGORY_AWS, True

    # 4. Auth Dotfiles
    if name in (".npmrc", ".netrc", ".pypirc", ".dockercfg"):
        return CATEGORY_DOTFILE, True

    # 5. Private keys / certificates
    if any(name.endswith(ext) for ext in (".pem", ".key", ".p8", ".pfx")):
        # Skip system or public bundle keys if in common cert folders
        if "cacert" not in name and "certificate" not in name:
            return CATEGORY_KEY, True

    # 6. Recovery codes
    if "recovery" in name and ("code" in name or "codes" in name) and name.endswith(".txt"):
        return CATEGORY_RECOVERY, True

    return None, False


def get_file_permissions(file_path):
    """Returns permissions formatted cleanly as 4-digit octal string (e.g. '0600', '0644')."""
    try:
        mode = file_path.stat().st_mode
        return oct(stat.S_IMODE(mode))[2:].zfill(4)
    except Exception:
        return "0644"


def scan_for_secrets(start_dir):
    """
    Recursively scans the given directory for secret files.
    Prunes heavy/cache folders immediately for blazing speed.
    """
    root_path = Path(start_dir).resolve()
    discovered = []
    seen_paths = set()

    for root, dirs, files in os.walk(root_path, followlinks=False):
        # Prune excluded directories in-place
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDE_DIR_NAMES
            and not d.startswith(".cache")
            and not (root_path == Path.home() and d in ("Library", "Applications", "Pictures", "Music", "Movies"))
        ]

        for file_name in files:
            file_path = Path(root) / file_name
            try:
                resolved = file_path.resolve()
            except Exception:
                continue

            if resolved in seen_paths or not file_path.is_file():
                continue

            category, is_match = classify_file(file_path)
            if is_match:
                seen_paths.add(resolved)
                discovered.append({
                    "path_obj": file_path,
                    "portable_path": normalize_to_home(file_path),
                    "category": category,
                    "size": file_path.stat().st_size,
                    "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(timespec="seconds"),
                    "permissions": get_file_permissions(file_path)
                })

    # Sort primarily by category, then by portable path
    discovered.sort(key=lambda x: (x["category"], x["portable_path"]))
    return discovered


# --- Master Markdown Generator ---
def generate_master_markdown(secrets_list, output_file):
    """Generates the master_secrets.md file with Markdown + YAML cards."""
    now = datetime.now().isoformat(timespec="seconds")
    system_info = f"{platform.system()} ({platform.release()}) - {platform.machine()}"

    lines = []
    lines.append("# Master Secrets Vault")
    lines.append(f"> Generated: `{now}`  ")
    lines.append(f"> Source Host: `{platform.node()}` ({system_info})  ")
    lines.append(f"> User Home: `{Path.home().as_posix()}`  ")
    lines.append(f"> Total Files: `{len(secrets_list)}`  ")
    lines.append("")
    lines.append("This document stores environment variables, developer keys, and credentials across projects.")
    lines.append("Each entry contains a YAML metadata card and exact file contents.")
    lines.append("")

    for idx, item in enumerate(secrets_list, start=1):
        path_obj = item["path_obj"]
        portable_path = item["portable_path"]
        category = item["category"]
        permissions = item["permissions"]
        size_bytes = item["size"]
        modified = item["modified"]

        is_bin = is_binary_file(path_obj)
        encoding_type = "base64" if is_bin else "utf-8"

        try:
            if is_bin:
                with open(path_obj, "rb") as f:
                    content_str = base64.b64encode(f.read()).decode("ascii")
                code_fence = "base64"
            else:
                with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
                    content_str = f.read()
                code_fence = "env" if category == CATEGORY_DOTENV else "text"
        except Exception as e:
            content_str = f"# Error reading file: {e}"
            code_fence = "text"

        lines.append("---")
        lines.append("")
        lines.append(f"## {idx}. [{category.upper()}] `{portable_path}`")
        lines.append("```yaml")
        lines.append(f"path: {portable_path}")
        lines.append(f"category: {category}")
        lines.append(f"permissions: \"{permissions}\"")
        lines.append(f"size_bytes: {size_bytes}")
        lines.append(f"modified: \"{modified}\"")
        lines.append(f"encoding: {encoding_type}")
        lines.append("```")
        lines.append(f"```{code_fence}")
        lines.append(content_str)
        if not content_str.endswith("\n"):
            lines.append("")
        lines.append("```")
        lines.append("")

    content = "\n".join(lines)
    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


# --- Master Markdown Parser ---
def parse_master_markdown(md_file_path):
    """
    Parses master_secrets.md and extracts all secrets entries
    with their YAML metadata cards and raw content.
    """
    if not os.path.exists(md_file_path):
        raise FileNotFoundError(f"File not found: {md_file_path}")

    with open(md_file_path, "r", encoding="utf-8", errors="replace") as f:
        full_text = f.read()

    # Split into sections by '---'
    raw_sections = full_text.split("\n---\n")
    parsed_entries = []

    # Regex to extract YAML block and subsequent code block
    yaml_regex = re.compile(r"```yaml\s*\n(.*?)\n```", re.DOTALL)
    code_regex = re.compile(r"```(?:[a-zA-Z0-9_-]*)\s*\n(.*?)\n```", re.DOTALL)

    for section in raw_sections:
        yaml_match = yaml_regex.search(section)
        if not yaml_match:
            continue

        yaml_content = yaml_match.group(1)
        meta = {}
        for line in yaml_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip().strip("\"'")

        # Find the code block immediately following the YAML block
        after_yaml = section[yaml_match.end():]
        content_match = code_regex.search(after_yaml)
        if not content_match:
            continue

        raw_payload = content_match.group(1)
        encoding_type = meta.get("encoding", "utf-8")

        if encoding_type == "base64":
            try:
                payload_bytes = base64.b64decode(raw_payload.strip())
                is_binary = True
            except Exception:
                payload_bytes = raw_payload.encode("utf-8")
                is_binary = False
        else:
            payload_bytes = raw_payload.encode("utf-8")
            is_binary = False

        # Ensure exact byte-for-byte fidelity using size_bytes metadata
        if "size_bytes" in meta:
            try:
                expected_size = int(meta["size_bytes"])
                if expected_size >= 0 and len(payload_bytes) > expected_size:
                    payload_bytes = payload_bytes[:expected_size]
            except ValueError:
                pass

        parsed_entries.append({
            "path": meta.get("path"),
            "category": meta.get("category", "unknown"),
            "permissions": meta.get("permissions", "0644"),
            "encoding": encoding_type,
            "is_binary": is_binary,
            "content_bytes": payload_bytes,
            "content_str": raw_payload if not is_binary else None
        })

    return parsed_entries


# --- CLI Commands: SCAN ---
def cmd_scan(args):
    scan_dir = expand_from_home(args.scan_dir)
    print(f"\n{color('🔍 Scanning for secrets in:', Style.BOLD)} {scan_dir}")
    print(color("   (Ignoring build/cache directories and dummy templates)", Style.DIM))

    secrets = scan_for_secrets(scan_dir)
    if not secrets:
        print(color("\nNo secrets or .env files found matching the search criteria.", Style.YELLOW))
        return

    print_secrets_table(secrets)
    print(f"\n{color('Total discovered:', Style.BOLD)} {len(secrets)} files.")


# --- CLI Commands: BACKUP ---
def cmd_backup(args):
    scan_dir = expand_from_home(args.scan_dir)
    output_path = Path(args.output).resolve()

    print(f"\n{color('🚀 Secrets Backup Initiated', Style.BOLD + Style.GREEN)}")
    print(f"   Root directory: {scan_dir}")
    print(f"   Target output:  {output_path}\n")

    secrets = scan_for_secrets(scan_dir)
    if not secrets:
        print(color("No secret files discovered. Exiting.", Style.YELLOW))
        return

    print_secrets_table(secrets)

    # Interactive Review & Exclusion
    selected_secrets = list(secrets)
    if not args.yes and sys.stdin.isatty():
        print(f"\n{color('Interactive Review:', Style.BOLD)}")
        print("All listed files will be bundled into the master backup.")
        user_input = input(
            color("To EXCLUDE any files, enter their numbers separated by commas (or press [Enter] to accept all): ", Style.CYAN)
        ).strip()

        if user_input:
            exclude_indices = set()
            for part in user_input.split(","):
                part = part.strip()
                if part.isdigit():
                    exclude_indices.add(int(part))
            selected_secrets = [s for idx, s in enumerate(secrets, start=1) if idx not in exclude_indices]
            print(f"Excluded {len(secrets) - len(selected_secrets)} files. {len(selected_secrets)} files remaining.")

    if not selected_secrets:
        print(color("No files selected for backup. Exiting.", Style.YELLOW))
        return

    generated_path = generate_master_markdown(selected_secrets, output_path)
    print(f"\n{color('✅ Successfully created master secrets vault!', Style.BOLD + Style.GREEN)}")
    print(f"   File: {color(str(generated_path), Style.BOLD)}")
    print(f"   Saved {len(selected_secrets)} secrets. Store this file securely!")


# --- CLI Commands: RESTORE ---
def cmd_restore(args):
    input_file = Path(args.input).resolve()
    dry_run = args.dry_run

    print(f"\n{color('📦 Secrets Restore Initiated', Style.BOLD + Style.CYAN)}")
    print(f"   Master vault file: {input_file}")
    if dry_run:
        print(color("   [DRY-RUN MODE: No files or directories will be modified]", Style.YELLOW + Style.BOLD))
    if args.base_dir:
        print(f"   Base directory override: {args.base_dir}")
    print("")

    entries = parse_master_markdown(input_file)
    if not entries:
        print(color("No entries found in master file.", Style.YELLOW))
        return

    print(f"Loaded {color(str(len(entries)), Style.BOLD)} secrets from vault.\n")

    restored_count = 0
    skipped_count = 0

    for idx, entry in enumerate(entries, start=1):
        portable_path = entry["path"]
        category = entry["category"]
        perms = entry["permissions"]
        content_bytes = entry["content_bytes"]
        is_binary = entry["is_binary"]

        dest_path = expand_from_home(portable_path, args.base_dir)
        print(f"[{idx}/{len(entries)}] {color(category.upper(), Style.MAGENTA)} -> {color(str(dest_path), Style.BOLD)}")

        # 1. Check parent directory
        parent_dir = dest_path.parent
        if not parent_dir.exists():
            if dry_run:
                print(f"   {color('Parent directory does not exist (dry-run):', Style.YELLOW)} {parent_dir}")
            else:
                if not args.yes and sys.stdin.isatty():
                    print(f"   {color('Parent directory does not exist:', Style.YELLOW)} {parent_dir}")
                    action = prompt_choice("   Action: [c]reate directory, [r]emap to new folder, [s]kip? ", ["c", "r", "s"], default="c")
                    if action == "s":
                        print(color("   Skipped.", Style.DIM))
                        skipped_count += 1
                        continue
                    elif action == "r":
                        new_parent = input("   Enter new directory path: ").strip()
                        parent_dir = Path(expand_from_home(new_parent)).resolve()
                        dest_path = parent_dir / dest_path.name

                parent_dir.mkdir(parents=True, exist_ok=True)
                print(f"   Created directory: {parent_dir}")

        # 2. Check if destination file already exists
        if dest_path.exists():
            if dry_run:
                print(f"   {color('File exists (dry-run): would prompt conflict resolution.', Style.YELLOW)}")
                restored_count += 1
                continue

            if args.yes:
                # Default non-interactive is overwrite
                action = "o"
            else:
                action = handle_conflict_interactive(dest_path, entry)

            if action == "s":
                print(color("   Skipped existing file.", Style.DIM))
                skipped_count += 1
                continue
            elif action == "b":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_dest = dest_path.with_name(f"{dest_path.name}.bak.{ts}")
                dest_path.rename(backup_dest)
                print(f"   Backed up existing file to: {color(str(backup_dest), Style.DIM)}")

        # 3. Write file
        if not dry_run:
            try:
                with open(dest_path, "wb") as f:
                    f.write(content_bytes)

                # 4. Set permissions (macOS / Linux)
                if platform.system() != "Windows" and perms:
                    try:
                        os.chmod(dest_path, int(perms, 8))
                    except Exception as pe:
                        print(f"   {color('Warning setting permissions:', Style.YELLOW)} {pe}")

                print(f"   {color('✓ Restored', Style.GREEN)} (perms: {perms})")
                restored_count += 1
            except Exception as e:
                print(f"   {color('✗ Error writing file:', Style.RED)} {e}")
                skipped_count += 1
        else:
            restored_count += 1

    print(f"\n{color('Restoration Summary:', Style.BOLD)}")
    print(f"   Restored: {color(str(restored_count), Style.GREEN)}")
    print(f"   Skipped:  {color(str(skipped_count), Style.YELLOW)}")


def handle_conflict_interactive(dest_path, entry):
    """Prompts the user with [s]kip, [o]verwrite, [b]ackup, [d]iff."""
    while True:
        choice = prompt_choice(
            f"   File exists! Conflict menu: [s]kip, [o]verwrite, [b]ackup & overwrite, [d]iff? ",
            ["s", "o", "b", "d"],
            default="b"
        )
        if choice != "d":
            return choice

        # Show diff
        if entry["is_binary"]:
            print(color("   Cannot diff binary file.", Style.YELLOW))
            continue

        try:
            with open(dest_path, "r", encoding="utf-8", errors="replace") as f:
                existing_lines = f.readlines()
            backup_lines = entry["content_bytes"].decode("utf-8", errors="replace").splitlines(keepends=True)

            diff = list(difflib.unified_diff(
                existing_lines, backup_lines,
                fromfile=f"Current ({dest_path.name})",
                tofile="Vault Backup"
            ))

            if not diff:
                print(color("   Files are identical!", Style.GREEN))
            else:
                print(f"\n{color('--- Diff (Current vs Vault) ---', Style.CYAN)}")
                for line in diff:
                    if line.startswith("+"):
                        print(color(line.rstrip(), Style.GREEN))
                    elif line.startswith("-"):
                        print(color(line.rstrip(), Style.RED))
                    elif line.startswith("@@"):
                        print(color(line.rstrip(), Style.CYAN))
                    else:
                        print(line.rstrip())
                print(color("--------------------------------", Style.CYAN) + "\n")
        except Exception as e:
            print(f"   Error calculating diff: {e}")


def prompt_choice(prompt_text, valid_choices, default=None):
    """Prompts user for single character choice."""
    if not sys.stdin.isatty():
        return default or valid_choices[0]
    while True:
        resp = input(color(prompt_text, Style.YELLOW)).strip().lower()
        if not resp and default:
            return default
        if resp in valid_choices:
            return resp
        print(f"Please enter one of: {', '.join(valid_choices)}")


def print_secrets_table(secrets):
    """Prints a styled terminal table listing all discovered secrets."""
    print("-" * 88)
    print(f"{'#':<4} {'CATEGORY':<18} {'PERMS':<8} {'SIZE':<10} {'PATH'}")
    print("-" * 88)
    for idx, s in enumerate(secrets, start=1):
        cat_color = {
            CATEGORY_DOTENV: Style.GREEN,
            CATEGORY_SSH: Style.CYAN,
            CATEGORY_AWS: Style.YELLOW,
            CATEGORY_DOTFILE: Style.BLUE,
            CATEGORY_KEY: Style.MAGENTA,
            CATEGORY_RECOVERY: Style.RED
        }.get(s["category"], Style.WHITE)

        size_str = f"{s['size']} B" if s['size'] < 1024 else f"{s['size']/1024:.1f} KB"
        print(f"{idx:<4} {color(s['category'], cat_color):<27} {s['permissions']:<8} {size_str:<10} {s['portable_path']}")
    print("-" * 88)


# --- Main Entry Point ---
def main():
    parser = argparse.ArgumentParser(
        description="Master Secrets Manager: Cross-platform backup & restore for .env and developer credentials."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan and list discovered secrets without saving.")
    scan_parser.add_argument("--scan-dir", "-s", default="~", help="Directory to scan (default: user home ~)")

    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Scan and bundle secrets into master_secrets.md.")
    backup_parser.add_argument("--scan-dir", "-s", default="~", help="Directory to scan (default: user home ~)")
    backup_parser.add_argument("--output", "-o", default="master_secrets.md", help="Output Markdown file (default: master_secrets.md)")
    backup_parser.add_argument("--yes", "-y", action="store_true", help="Skip interactive exclusion and save all.")

    # Restore command
    restore_parser = subparsers.add_parser("restore", help="Restore secrets from master_secrets.md back to original locations.")
    restore_parser.add_argument("--input", "-i", default="master_secrets.md", help="Input master file (default: master_secrets.md)")
    restore_parser.add_argument("--base-dir", "-b", default=None, help="Optional base directory to rebase paths onto")
    restore_parser.add_argument("--dry-run", "-d", action="store_true", help="Simulate restoration without writing files.")
    restore_parser.add_argument("--yes", "-y", action="store_true", help="Non-interactive mode (overwrite existing conflicts).")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "backup":
        cmd_backup(args)
    elif args.command == "restore":
        cmd_restore(args)


if __name__ == "__main__":
    main()
