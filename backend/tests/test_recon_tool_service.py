from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import TestCase
from unittest.mock import patch


# Load this small service in isolation so the unit test does not import every
# optional backend integration through app.services.__init__.
config_module = ModuleType("app.config")
config_module.settings = SimpleNamespace()
sys.modules.setdefault("app.config", config_module)
module_path = Path(__file__).parents[1] / "app" / "services" / "recon_tool_service.py"
module_spec = importlib.util.spec_from_file_location(
    "recon_tool_service_under_test",
    module_path,
)
assert module_spec and module_spec.loader
recon_tool_service = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = recon_tool_service
module_spec.loader.exec_module(recon_tool_service)


def make_config(tmp_path, **overrides):
    values = {
        "pd_tools_path": str(tmp_path / "tools"),
        "nmap_path": str(tmp_path / "nmap"),
        "chromium_path": str(tmp_path / "chromium"),
        "recon_tool_probe_timeout_seconds": 5,
    }
    for spec in recon_tool_service.OPTIONAL_RECON_TOOLS:
        values[spec.enabled_setting] = False
    values.update(overrides)
    return SimpleNamespace(**values)


class ReconToolServiceTests(TestCase):
    def test_droopescan_uses_supported_help_probe(self):
        spec = next(
            item
            for item in recon_tool_service.OPTIONAL_RECON_TOOLS
            if item.name == "droopescan"
        )

        self.assertEqual(spec.probe_args, ("--help",))

    def test_enabled_registry_includes_core_and_selected_optional_tools(self):
        temp_path = Path("/isolated-test")
        config = make_config(
            temp_path,
            sublist3r_enabled=True,
            nikto_enabled=True,
        )

        names = [
            spec.name
            for spec in recon_tool_service.enabled_recon_tool_specs(config)
        ]

        self.assertEqual(
            names[:7],
            [
                "subfinder",
                "dnsx",
                "naabu",
                "nmap",
                "httpx",
                "nuclei",
                "gowitness",
            ],
        )
        self.assertIn("sublist3r", names)
        self.assertIn("nikto", names)
        self.assertNotIn("dirbuster", names)

    def test_tool_paths_use_configured_volume_and_system_path(self):
        temp_path = Path("/isolated-test")
        config = make_config(temp_path, katana_enabled=True)

        paths = recon_tool_service.enabled_recon_tool_paths(config)

        self.assertEqual(paths["subfinder"], temp_path / "tools" / "subfinder")
        self.assertEqual(paths["katana"], temp_path / "tools" / "katana")
        self.assertEqual(paths["nmap"], temp_path / "nmap")

    def test_failed_startup_probe_marks_executable_unavailable(self):
        executable = Path("/isolated-test/scanner")
        config = make_config(Path("/isolated-test"))
        config.nmap_path = str(executable)
        spec = recon_tool_service.ReconToolSpec(
            "scanner",
            system_path_setting="nmap_path",
            probe_args=("--version",),
        )

        completed = subprocess.CompletedProcess(
            [str(executable), "--version"],
            127,
            stdout="",
            stderr="missing dependency",
        )
        with (
            patch.object(recon_tool_service.Path, "is_file", return_value=True),
            patch.object(recon_tool_service.os, "access", return_value=True),
            patch.object(recon_tool_service.subprocess, "run", return_value=completed),
        ):
            status = recon_tool_service._inspect_tool(
                spec,
                config=config,
                probe=True,
            )

        self.assertTrue(status["probed"])
        self.assertFalse(status["available"])
        self.assertEqual(status["error"], "Startup probe exited with code 127")
        self.assertEqual(status["version"], "missing dependency")

    def test_unsafe_tool_without_probe_is_not_reported_ready(self):
        executable = Path("/isolated-test/scanner")
        config = make_config(Path("/isolated-test"))
        config.nmap_path = str(executable)
        spec = recon_tool_service.ReconToolSpec(
            "scanner",
            system_path_setting="nmap_path",
        )

        with (
            patch.object(recon_tool_service.Path, "is_file", return_value=True),
            patch.object(recon_tool_service.os, "access", return_value=True),
        ):
            status = recon_tool_service._inspect_tool(spec, config=config, probe=True)

        self.assertFalse(status["available"])
        self.assertFalse(status["probed"])
        self.assertEqual(
            status["error"],
            "No safe non-scanning startup probe is defined",
        )
