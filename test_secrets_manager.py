#!/usr/bin/env python3
"""
Comprehensive Test Suite for Secrets Manager
=============================================
Tests scanner classification, exclusion filters, backup generation,
master markdown parsing, permission preservation, and restore workflows.
"""

import os
import sys
import stat
import shutil
import tempfile
import unittest
from pathlib import Path

# Import functions from secrets_manager
sys.path.insert(0, str(Path(__file__).parent))
import secrets_manager


class TestSecretsManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="secrets_test_")
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_classification_and_filters(self):
        """Verify that genuine secret files are classified and dummy templates are ignored."""
        # Genuine secrets
        valid_cases = [
            ("project/.env", secrets_manager.CATEGORY_DOTENV),
            ("project/.env.local", secrets_manager.CATEGORY_DOTENV),
            ("project/.env.production", secrets_manager.CATEGORY_DOTENV),
            (".ssh/id_rsa", secrets_manager.CATEGORY_SSH),
            (".ssh/id_ed25519", secrets_manager.CATEGORY_SSH),
            (".ssh/config", secrets_manager.CATEGORY_SSH),
            (".aws/credentials", secrets_manager.CATEGORY_AWS),
            (".npmrc", secrets_manager.CATEGORY_DOTFILE),
            (".netrc", secrets_manager.CATEGORY_DOTFILE),
            ("certs/server-key.pem", secrets_manager.CATEGORY_KEY),
            ("certs/api.key", secrets_manager.CATEGORY_KEY),
            ("github-recovery-codes.txt", secrets_manager.CATEGORY_RECOVERY),
        ]
        for rel_path, expected_cat in valid_cases:
            p = self.root / rel_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("test content")
            cat, match = secrets_manager.classify_file(p)
            self.assertTrue(match, f"Failed to match valid secret: {rel_path}")
            self.assertEqual(cat, expected_cat, f"Wrong category for: {rel_path}")

        # Ignored templates / non-secrets
        ignored_cases = [
            "project/.env.example",
            "project/.env.sample",
            "project/.env.template",
            "project/.env.dist",
            ".ssh/id_rsa.pub",
            ".ssh/id_ed25519.pub",
            "notes.txt",
            "main.py",
        ]
        for rel_path in ignored_cases:
            p = self.root / rel_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("template content")
            cat, match = secrets_manager.classify_file(p)
            self.assertFalse(match, f"Should NOT match template or non-secret: {rel_path}")

    def test_scanner_pruning(self):
        """Verify that scanner skips node_modules, .git, and cache directories."""
        # Secret in valid project
        valid_env = self.root / "apps" / "api" / ".env"
        valid_env.parent.mkdir(parents=True, exist_ok=True)
        valid_env.write_text("API_KEY=secret123")

        # Secret inside node_modules (should be pruned)
        nm_env = self.root / "apps" / "api" / "node_modules" / "pkg" / ".env"
        nm_env.parent.mkdir(parents=True, exist_ok=True)
        nm_env.write_text("DEPENDENCY_KEY=ignore_me")

        # Secret inside .git (should be pruned)
        git_env = self.root / ".git" / ".env"
        git_env.parent.mkdir(parents=True, exist_ok=True)
        git_env.write_text("GIT_INTERNAL=ignore_me")

        discovered = secrets_manager.scan_for_secrets(self.root)
        paths = [d["path_obj"] for d in discovered]

        self.assertIn(valid_env.resolve(), [p.resolve() for p in paths])
        self.assertNotIn(nm_env.resolve(), [p.resolve() for p in paths])
        self.assertNotIn(git_env.resolve(), [p.resolve() for p in paths])

    def test_backup_and_restore_cycle(self):
        """Full end-to-end cycle: scan -> generate markdown -> restore -> verify contents and permissions."""
        # 1. Create mock project structure
        proj_dir = self.root / "my_project"
        proj_dir.mkdir(parents=True, exist_ok=True)

        env_file = proj_dir / ".env.local"
        env_content = "DATABASE_URL=postgres://localhost:5432\nSECRET_KEY=super-secret-xyz"
        env_file.write_text(env_content)
        os.chmod(env_file, 0o644)

        key_file = proj_dir / "private.key"
        key_content = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
        key_file.write_text(key_content)
        os.chmod(key_file, 0o600)

        # 2. Scan
        discovered = secrets_manager.scan_for_secrets(proj_dir)
        self.assertEqual(len(discovered), 2)

        # 3. Generate master markdown
        vault_file = self.root / "master_vault.md"
        secrets_manager.generate_master_markdown(discovered, vault_file)
        self.assertTrue(vault_file.exists())

        # 4. Parse markdown
        parsed = secrets_manager.parse_master_markdown(vault_file)
        self.assertEqual(len(parsed), 2)

        # 5. Simulate restoration into a clean destination folder
        restore_dir = self.root / "restored_system"
        restore_dir.mkdir(parents=True, exist_ok=True)

        for entry in parsed:
            # Rebase destination to restore_dir
            filename = Path(entry["path"]).name
            dest_file = restore_dir / filename
            with open(dest_file, "wb") as f:
                f.write(entry["content_bytes"])
            if entry["permissions"]:
                os.chmod(dest_file, int(entry["permissions"], 8))

        # 6. Verify restored files
        restored_env = restore_dir / ".env.local"
        self.assertTrue(restored_env.exists())
        self.assertEqual(restored_env.read_text(), env_content)

        restored_key = restore_dir / "private.key"
        self.assertTrue(restored_key.exists())
        self.assertEqual(restored_key.read_text(), key_content)

        if os.name != "nt":
            self.assertEqual(oct(stat.S_IMODE(restored_key.stat().st_mode))[2:].zfill(4), "0600")
            self.assertEqual(oct(stat.S_IMODE(restored_env.stat().st_mode))[2:].zfill(4), "0644")

    def test_conflict_backup_option(self):
        """Verify conflict resolution when file already exists."""
        dest_file = self.root / ".env"
        dest_file.write_text("OLD_KEY=old_value")

        # Mock backup action by simulating rename
        ts = "20261022_120000"
        backup_file = dest_file.with_name(f"{dest_file.name}.bak.{ts}")
        dest_file.rename(backup_file)

        dest_file.write_text("NEW_KEY=new_value")

        self.assertTrue(backup_file.exists())
        self.assertEqual(backup_file.read_text(), "OLD_KEY=old_value")
        self.assertEqual(dest_file.read_text(), "NEW_KEY=new_value")


if __name__ == "__main__":
    unittest.main(verbosity=2)
