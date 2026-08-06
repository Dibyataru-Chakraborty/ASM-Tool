"""Shared scanner executable registry and non-scanning startup checks."""

from __future__ import annotations

import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import settings


@dataclass(frozen=True)
class ReconToolSpec:
    name: str
    enabled_setting: str | None = None
    system_path_setting: str | None = None
    probe_args: tuple[str, ...] = ()
    accepted_return_codes: tuple[int, ...] = (0,)


CORE_RECON_TOOLS: tuple[ReconToolSpec, ...] = (
    ReconToolSpec("subfinder", probe_args=("-version",)),
    ReconToolSpec("dnsx", probe_args=("-version",)),
    ReconToolSpec("naabu", probe_args=("-version",)),
    ReconToolSpec(
        "nmap",
        system_path_setting="nmap_path",
        probe_args=("--version",),
    ),
    ReconToolSpec("httpx", probe_args=("-version",)),
    ReconToolSpec("nuclei", probe_args=("-version",)),
    ReconToolSpec("gowitness", probe_args=("version",)),
)

OPTIONAL_RECON_TOOLS: tuple[ReconToolSpec, ...] = (
    ReconToolSpec("sublist3r", "sublist3r_enabled", probe_args=("-h",)),
    ReconToolSpec("uncover", "uncover_enabled", probe_args=("-version",)),
    ReconToolSpec(
        "waybackurls",
        "waybackurls_enabled",
        probe_args=("-h",),
        accepted_return_codes=(0, 2),
    ),
    ReconToolSpec("katana", "katana_enabled", probe_args=("-version",)),
    ReconToolSpec("paramspider", "paramspider_enabled", probe_args=("--help",)),
    ReconToolSpec("dirsearch", "dirsearch_enabled", probe_args=("--help",)),
    ReconToolSpec(
        "dirb",
        "dirb_enabled",
        probe_args=("-h",),
        accepted_return_codes=(0, 1, 2),
    ),
    # DirBuster can launch a GUI and LazyRecon treats its first argument as a
    # target, so neither has a safe generic command probe. They remain disabled
    # by default and will not be marked ready if explicitly enabled.
    ReconToolSpec("dirbuster", "dirbuster_enabled"),
    ReconToolSpec("wappalyzer", "wappalyzer_enabled", probe_args=("--help",)),
    ReconToolSpec("wpscan", "wpscan_enabled", probe_args=("--version",)),
    ReconToolSpec("droopescan", "droopescan_enabled", probe_args=("--help",)),
    ReconToolSpec("secretfinder", "secretfinder_enabled", probe_args=("-h",)),
    ReconToolSpec("xsstrike", "xsstrike_enabled", probe_args=("--help",)),
    ReconToolSpec("xssvibes", "xssvibes_enabled", probe_args=("-h",)),
    ReconToolSpec("nikto", "nikto_enabled", probe_args=("-Version",)),
    ReconToolSpec("lazyrecon", "lazyrecon_enabled"),
)

ALL_RECON_TOOLS = CORE_RECON_TOOLS + OPTIONAL_RECON_TOOLS
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _is_enabled(spec: ReconToolSpec, config: Any) -> bool:
    return spec.enabled_setting is None or bool(getattr(config, spec.enabled_setting))


def resolve_recon_tool_path(spec: ReconToolSpec, config: Any = settings) -> Path:
    if spec.system_path_setting:
        return Path(str(getattr(config, spec.system_path_setting)))
    return Path(str(config.pd_tools_path)) / spec.name


def enabled_recon_tool_specs(config: Any = settings) -> tuple[ReconToolSpec, ...]:
    return tuple(spec for spec in ALL_RECON_TOOLS if _is_enabled(spec, config))


def enabled_recon_tool_paths(config: Any = settings) -> dict[str, Path]:
    return {
        spec.name: resolve_recon_tool_path(spec, config)
        for spec in enabled_recon_tool_specs(config)
    }


def _output_summary(stdout: str | None, stderr: str | None) -> str | None:
    text = "\n".join(part for part in (stdout, stderr) if part)
    text = _ANSI_ESCAPE_RE.sub("", text)
    for line in text.splitlines():
        clean = " ".join(line.split())
        if clean:
            return clean[:500]
    return None


def _inspect_tool(
    spec: ReconToolSpec,
    *,
    config: Any,
    probe: bool,
) -> dict[str, Any]:
    path = resolve_recon_tool_path(spec, config)
    executable = path.is_file() and os.access(path, os.X_OK)
    result: dict[str, Any] = {
        "enabled": _is_enabled(spec, config),
        "available": executable,
        "path": str(path),
        "probed": False,
    }
    if not executable:
        result["error"] = "Executable file is missing or is not executable"
        return result
    if not probe:
        return result
    if not spec.probe_args:
        result["available"] = False
        result["error"] = "No safe non-scanning startup probe is defined"
        return result

    result["probed"] = True
    command = [str(path), *spec.probe_args]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=max(1, int(config.recon_tool_probe_timeout_seconds)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["available"] = False
        result["error"] = "Startup probe timed out"
        return result
    except OSError as exc:
        result["available"] = False
        result["error"] = f"Could not start executable: {exc}"
        return result

    summary = _output_summary(completed.stdout, completed.stderr)
    if summary:
        result["version"] = summary
    if completed.returncode not in spec.accepted_return_codes:
        result["available"] = False
        result["error"] = f"Startup probe exited with code {completed.returncode}"
    return result


def inspect_recon_tools(
    *,
    probe: bool,
    config: Any = settings,
) -> dict[str, dict[str, Any]]:
    """Inspect every enabled scanner, optionally starting safe help/version probes."""
    specs = enabled_recon_tool_specs(config)
    if not probe or len(specs) < 2:
        return {
            spec.name: _inspect_tool(spec, config=config, probe=probe)
            for spec in specs
        }

    max_workers = min(8, len(specs))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            spec.name: executor.submit(_inspect_tool, spec, config=config, probe=True)
            for spec in specs
        }
        return {name: future.result() for name, future in futures.items()}


def inspect_chromium(*, probe: bool, config: Any = settings) -> dict[str, Any]:
    spec = ReconToolSpec(
        "chromium",
        system_path_setting="chromium_path",
        probe_args=("--version",),
    )
    return _inspect_tool(spec, config=config, probe=probe)


def unavailable_tool_messages(statuses: dict[str, dict[str, Any]]) -> list[str]:
    messages = []
    for name, state in statuses.items():
        if state.get("available"):
            continue
        reason = state.get("error") or "unavailable"
        messages.append(f"{name} ({reason})")
    return messages
