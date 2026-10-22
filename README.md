# 🔐 Master Secrets Manager

A lightweight, zero-dependency, cross-platform CLI tool for backing up and restoring `.env` files, SSH keys, cloud credentials, and secret files across projects before resetting your operating system.

---

## 🚀 Features

- **Zero Dependencies**: Uses only the Python 3 standard library. Runs out of the box on macOS, Linux, and Windows without `pip install`.
- **Easily Understandable Format**: Saves everything into a single Markdown document (`master_secrets.md`) with per-file YAML metadata cards and syntax-highlighted code blocks.
- **Smart Discovery**: Automatically discovers `.env`, `.env.local`, `.env.production`, `~/.ssh` keys, `~/.aws` credentials, `.npmrc`, `.netrc`, `*.pem`, `*.key`, and recovery codes.
- **Noise Filtering**: Automatically ignores dummy templates (`.env.example`, `.env.sample`, `.env.template`) and skips build/cache directories (`node_modules`, `.git`, `.venv`, `dist`, `Library`, etc.).
- **Interactive Review & Conflict Resolution**:
  - Exclude unwanted files before generating the backup.
  - Interactive conflict menu on restore: `[s]kip`, `[o]verwrite`, `[b]ackup (.bak) & overwrite`, or `[d]iff`.
  - Re-applies exact file permissions (`chmod 0600` for private keys, `chmod 0644` for configs).

---

## 📂 File Structure

```text
secrets-manager/
├── secrets_manager.py   # Main cross-platform Python CLI tool
├── backup.sh            # Quick runner for backup
├── restore.sh           # Quick runner for restore
├── test_secrets_manager.py # Test suite
├── master_secrets.md    # Generated vault file (local only, git-ignored)
└── README.md            # Documentation
```

---

## 🛠️ Usage

### 1. Preview Discovered Secrets (Scan Only)
To inspect what secret files exist without generating any files:
```bash
python3 secrets_manager.py scan
```
Or scan a specific folder:
```bash
python3 secrets_manager.py scan --scan-dir ~/Documents
```

---

### 2. Back Up All Secrets
Scan your system, review discovered files, and generate `master_secrets.md`:
```bash
./backup.sh
# OR
python3 secrets_manager.py backup
```

#### Flags:
- `--scan-dir <path>`: Root folder to search (default is `~`).
- `--output <path>`: Output file path (default is `master_secrets.md`).
- `--yes`: Non-interactive mode (automatically includes all discovered files).

> [!IMPORTANT]
> **Before Resetting Your System:**
> Copy the generated `master_secrets.md` (and `secrets_manager.py`) to an external USB drive, private cloud storage, or password manager.

---

### 3. Restore Secrets (After System Reset)
On your fresh machine, navigate to the folder with `master_secrets.md` and run:

#### Test first (Dry Run):
```bash
python3 secrets_manager.py restore --dry-run
```

#### Perform actual restore:
```bash
./restore.sh
# OR
python3 secrets_manager.py restore
```

#### Flags:
- `--input <path>`: Path to master file (default: `master_secrets.md`).
- `--dry-run`: Preview what files would be restored without making any changes.
- `--base-dir <path>`: Rebase paths to a different base directory if your folder layout changed.
- `--yes`: Non-interactive mode (automatically overwrites existing files).

---

## 📄 Master File Format (`master_secrets.md`)

Each secret is structured with a YAML metadata card followed by the verbatim file content:

````markdown
## 1. [DOTENV] `~/Documents/my-project/.env`
```yaml
path: ~/Documents/my-project/.env
category: dotenv
permissions: "0644"
size_bytes: 428
modified: "2026-10-01T15:23:00"
encoding: utf-8
```
```env
PORT=3000
DATABASE_URL=postgresql://...
```
````
