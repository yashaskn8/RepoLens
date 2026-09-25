"""Operator commands for LangGraph checkpoint schema initialization."""

from __future__ import annotations

import argparse
import asyncio

from app.agents.checkpointer import setup_analysis_checkpointer


async def _run(command: str) -> None:
    if command != "setup":
        raise ValueError("Unsupported checkpoint command.")
    backend = await setup_analysis_checkpointer()
    print(f"Initialized LangGraph checkpoint schema for backend={backend.value}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage RepoLens LangGraph checkpoint storage.")
    parser.add_argument("command", choices=("setup",))
    args = parser.parse_args()
    asyncio.run(_run(args.command))


if __name__ == "__main__":
    main()
