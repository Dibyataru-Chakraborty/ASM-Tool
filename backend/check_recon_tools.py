"""Run non-scanning startup checks for every enabled recon executable."""

from __future__ import annotations

import json

from app.config import settings
from app.services.recon_tool_service import inspect_chromium, inspect_recon_tools


def main() -> int:
    tools = inspect_recon_tools(probe=True, config=settings)
    chromium = inspect_chromium(probe=True, config=settings)
    ready = all(state["available"] for state in tools.values()) and chromium["available"]
    print(json.dumps(
        {
            "ready": ready,
            "tools": tools,
            "chromium": chromium,
        },
        indent=2,
        sort_keys=True,
    ))
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
