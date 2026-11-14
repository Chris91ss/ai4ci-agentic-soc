"""Backend of the SOC console (FastAPI, server-sent events)."""

from agentic_soc.api.app import create_app
from agentic_soc.api.service import ConsoleService, ReadOnlyError, jsonable

__all__ = ["ConsoleService", "ReadOnlyError", "create_app", "jsonable"]
