import importlib.util, os, tempfile, unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "container_init", Path(__file__).parents[1] / "scripts/container_init.py"
)
init = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init)


class ContainerInitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        p = Path(self.temp.name)
        self.seed = p / "seed"
        self.run = p / "run"
        self.data = p / "data"
        self.seed.mkdir()
        for name in [
            "feishu-app-secret",
            "internal-key",
            "state-key",
            "jwks.json",
            "cookie-keys.json",
            "auth-db-key",
        ]:
            f = self.seed / name
            f.write_text("synthetic")
            f.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def execute(self):
        init.initialize(
            self.seed,
            self.run,
            self.data,
            "cli_test_app",
            False,
            os.getuid(),
            os.getgid(),
        )

    def test_initialize_and_preserve_cli_config(self):
        self.execute()
        config = self.data / ".lark-cli/config.json"
        old = config.read_bytes()
        self.execute()
        self.assertEqual(old, config.read_bytes())

    def test_reject_cli_directory_symlink(self):
        self.data.mkdir()
        target = Path(self.temp.name) / "target"
        target.mkdir()
        (self.data / ".lark-cli").symlink_to(target)
        with self.assertRaises(OSError):
            self.execute()
        self.assertEqual(list(target.iterdir()), [])

    def test_reject_cli_config_symlink(self):
        cli = self.data / ".lark-cli"
        cli.mkdir(parents=True)
        target = Path(self.temp.name) / "target"
        target.write_text("unchanged")
        (cli / "config.json").symlink_to(target)
        with self.assertRaises(OSError):
            self.execute()
        self.assertEqual(target.read_text(), "unchanged")

    def test_atomic_runtime_copy_never_follows_symlink(self):
        self.run.mkdir()
        target = Path(self.temp.name) / "target"
        target.write_text("unchanged")
        (self.run / "internal-key").symlink_to(target)
        self.execute()
        self.assertFalse((self.run / "internal-key").is_symlink())
        self.assertEqual(target.read_text(), "unchanged")
