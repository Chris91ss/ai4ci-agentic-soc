"""Command-line entry point: ``soc <command>``."""

from __future__ import annotations

import typer
from rich.console import Console

from agentic_soc import __version__

app = typer.Typer(
    name="soc",
    help="Agentic SOC: simulator, pipeline, detectors, triage agent and evaluation.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def main() -> None:
    """Agentic SOC command-line interface."""


@app.command()
def version() -> None:
    """Print the package version."""
    console.print(f"agentic-soc {__version__}")


if __name__ == "__main__":
    app()
