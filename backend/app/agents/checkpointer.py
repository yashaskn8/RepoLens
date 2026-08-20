"""LangGraph official SQLite checkpointer integration for durable execution."""

from contextlib import asynccontextmanager
import os
from typing import AsyncIterator, Optional
import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from app.core.config import get_settings


@asynccontextmanager
async def get_sqlite_checkpointer(
    db_path: Optional[str] = None,
) -> AsyncIterator[AsyncSqliteSaver]:
    """Provide an initialized official LangGraph AsyncSqliteSaver checkpointer.
    
    Supports :memory: for tests and durable SQLite database files for local development.
    Zero Docker / external services required.
    """
    settings = get_settings()
    target_path = db_path if db_path is not None else settings.CHECKPOINT_DB_FILE

    async with aiosqlite.connect(target_path) as conn:
        checkpointer = AsyncSqliteSaver(conn)
        await checkpointer.setup()
        yield checkpointer
