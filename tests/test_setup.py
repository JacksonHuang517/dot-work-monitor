import importlib.util, tempfile, unittest, stat
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "project_setup", Path(__file__).parents[1] / "scripts/setup.py"
)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_private_files_and_key_stability(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "seed"
            setup.generate(p, "synthetic-app-secret", "synthetic-mail-password")
            initial = {
                name: (p / name).read_bytes()
                for name in ["state-key", "auth-db-key", "jwks.json", "internal-key"]
            }
            for name in setup.SECRET_NAMES:
                self.assertEqual(stat.S_IMODE((p / name).stat().st_mode), 0o600)
            setup.generate(p, "updated-app-secret", "")
            self.assertEqual(
                (p / "feishu-app-secret").read_text(), "updated-app-secret"
            )
            self.assertEqual(
                (p / "mail-password").read_text(), "synthetic-mail-password"
            )
            self.assertEqual(initial, {k: (p / k).read_bytes() for k in initial})

    def test_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / "target").mkdir()
            (p / "link").symlink_to(p / "target")
            with self.assertRaises(ValueError):
                setup.generate(p / "link", "synthetic", "")

    def test_origin_validation(self):
        self.assertEqual(
            setup.validate_origin("https://monitor.example.com/"),
            "https://monitor.example.com",
        )
        for origin in [
            "http://example.com",
            "https://example.com/private",
            "https://user:pass@example.com",
            "https://example.com?x=1",
        ]:
            with self.assertRaises(ValueError):
                setup.validate_origin(origin)
