import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from share_claude import cli


class CredentialFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = cli.FileStore(self.root / ".claude")
        self.original = {"accessToken": "original-access", "refreshToken": "original-refresh"}
        self.shared = {"accessToken": "shared-access", "refreshToken": "shared-refresh"}
        self.store.write_blob({"claudeAiOauth": self.original, "mcpOAuth": {"private": "keep"}})
        self.archive = self.root / "claude.zip"

    def test_share_use_restore_preserves_mcp_and_removes_backup(self):
        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli.getpass, "getpass", side_effect=["long-passcode-1234", "long-passcode-1234"]
        ):
            self.assertEqual(cli.main(["share", "--output", str(self.archive)]), 0)
        self.assertEqual(cli._read_archive(self.archive, "long-passcode-1234"), self.original)
        self.assertNotIn(b"private", self.archive.read_bytes())

        self.store.write_blob({"claudeAiOauth": self.shared, "mcpOAuth": {"private": "keep"}})
        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli, "_status_logged_in", return_value=True
        ), patch.object(cli, "_reject_environment_auth"), patch.object(
            cli.getpass, "getpass", return_value="long-passcode-1234"
        ), patch("builtins.input", return_value="yes"):
            self.assertEqual(cli.main(["use", str(self.archive)]), 0)
        self.assertEqual(self.store.read_blob()["claudeAiOauth"], self.original)
        self.assertEqual(self.store.read_blob()["mcpOAuth"], {"private": "keep"})
        self.assertTrue(self.store.backup_exists())
        self.assertEqual(os.stat(self.store.backup_path).st_mode & 0o777, 0o600)

        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli, "_reject_environment_auth"
        ):
            self.assertEqual(cli.main(["restore"]), 0)
        self.assertEqual(self.store.read_blob()["claudeAiOauth"], self.shared)
        self.assertFalse(self.store.backup_exists())

    def test_wrong_passcode_does_not_change_credential(self):
        cli._write_archive(self.archive, self.shared, "long-passcode-1234")
        before = self.store.path.read_bytes()
        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli, "_reject_environment_auth"
        ), patch.object(cli.getpass, "getpass", return_value="wrong-passcode"):
            self.assertEqual(cli.main(["use", str(self.archive)]), 1)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertFalse(self.store.backup_exists())

    def test_declining_replacement_leaves_no_backup(self):
        cli._write_archive(self.archive, self.shared, "long-passcode-1234")
        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli, "_status_logged_in", return_value=True
        ), patch.object(cli, "_reject_environment_auth"), patch.object(
            cli.getpass, "getpass", return_value="long-passcode-1234"
        ), patch("builtins.input", return_value="no"):
            self.assertEqual(cli.main(["use", str(self.archive)]), 0)
        self.assertEqual(self.store.read_blob()["claudeAiOauth"], self.original)
        self.assertFalse(self.store.backup_exists())

    def test_second_import_cannot_replace_backup(self):
        cli._write_archive(self.archive, self.shared, "long-passcode-1234")
        self.store.save_backup(self.original)
        with patch.object(cli, "_store", return_value=self.store), patch.object(
            cli, "_reject_environment_auth"
        ), patch.object(cli.getpass, "getpass", return_value="long-passcode-1234"):
            self.assertEqual(cli.main(["use", str(self.archive)]), 1)
        self.assertEqual(self.store.read_blob()["claudeAiOauth"], self.original)
        self.assertEqual(self.store.read_backup(), self.original)

    @unittest.skipUnless(sys.platform == "darwin", "macOS Keychain only")
    def test_keychain_backup_and_restore_with_dummy_credentials(self):
        store = cli.KeychainStore(self.root / ".claude")
        suffix = uuid4().hex
        current_service = "share-claude-test-current-" + suffix
        backup_service = "share-claude-test-backup-" + suffix
        with patch.object(cli, "KEYCHAIN_SERVICE", current_service), patch.object(
            cli, "BACKUP_KEYCHAIN_SERVICE", backup_service
        ):
            try:
                store.write_blob({"claudeAiOauth": self.original, "mcpOAuth": {"x": "keep"}})
                store.save_backup(self.original)
                self.assertTrue(store.backup_exists())
                store.write_blob({"claudeAiOauth": self.shared, "mcpOAuth": {"x": "keep"}})
                restored = store.read_backup()
                blob = store.read_blob()
                blob["claudeAiOauth"] = restored
                store.write_blob(blob)
                store.remove_backup()
                self.assertEqual(store.read_blob()["claudeAiOauth"], self.original)
                self.assertEqual(store.read_blob()["mcpOAuth"], {"x": "keep"})
                self.assertFalse(store.backup_exists())
            finally:
                store._call("delete", current_service)
                store._call("delete", backup_service)
                store.backup_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
