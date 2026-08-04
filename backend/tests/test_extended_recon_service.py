from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import TestCase


config_module = ModuleType("app.config")
config_module.settings = SimpleNamespace()
sys.modules.setdefault("app.config", config_module)
module_path = Path(__file__).parents[1] / "app" / "services" / "extended_recon_service.py"
module_spec = importlib.util.spec_from_file_location(
    "extended_recon_service_under_test",
    module_path,
)
assert module_spec and module_spec.loader
extended_recon_service = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = extended_recon_service
module_spec.loader.exec_module(extended_recon_service)


class ExtendedReconServiceTests(TestCase):
    def test_dirsearch_uses_v05_json_output_option(self):
        command = extended_recon_service.build_dirsearch_command(
            Path("/tools/dirsearch"),
            "https://app.example.com/",
            Path("/tmp/report.json"),
            20,
        )

        self.assertNotIn("--format", command)
        self.assertEqual(command[command.index("-O") + 1], "json")
        self.assertEqual(Path(command[command.index("-o") + 1]), Path("/tmp/report.json"))

    def test_nuclei_targets_prioritize_origins_then_parameters(self):
        targets = extended_recon_service.select_nuclei_targets(
            [
                "https://app.example.com/deep/path",
                "https://app.example.com/search?q=test",
                "https://api.example.com/v1/users",
                "https://off-scope.test/ignored",
                "https://app.example.com/deep/path",
            ],
            "example.com",
            4,
        )

        self.assertEqual(
            targets,
            [
                "https://api.example.com/",
                "https://app.example.com/",
                "https://app.example.com/search?q=test",
                "https://api.example.com/v1/users",
            ],
        )

    def test_nuclei_target_limit_is_enforced(self):
        targets = extended_recon_service.select_nuclei_targets(
            [
                "https://a.example.com/",
                "https://b.example.com/",
                "https://c.example.com/",
            ],
            "example.com",
            2,
        )

        self.assertEqual(len(targets), 2)
