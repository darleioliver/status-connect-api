import asyncio
from pathlib import Path
from typing import List

from sqlalchemy import text

from database import Base, engine
# Importa os modelos para garantir que todos estejam registrados em Base.metadata
import models  # noqa: F401


_migration_lock = asyncio.Lock()
_schema_verified = False

_SQL_MIGRATION_FILE = Path(__file__).resolve().parent / "migrations" / "001_add_push_tables.sql"

_POSTGRES_PUSH_STATEMENTS: List[str] = [
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_premium BOOLEAN NOT NULL DEFAULT FALSE
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS premium_expires_at TIMESTAMP WITHOUT TIME ZONE NULL
    """,
    "CREATE INDEX IF NOT EXISTS ix_users_premium_expires_at ON users (premium_expires_at)",
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS last_active_date VARCHAR(16) DEFAULT ''
    """,
    """
    CREATE TABLE IF NOT EXISTS device_tokens (
        id SERIAL PRIMARY KEY,
        fcm_token VARCHAR(512) NOT NULL,
        user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        device_platform VARCHAR(20) NOT NULL DEFAULT 'android',
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        last_seen_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uq_device_tokens_fcm_token UNIQUE (fcm_token)
    )
    """,
    "ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL",
    "ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS device_platform VARCHAR(20) NOT NULL DEFAULT 'android'",
    "ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_device_tokens_fcm_token ON device_tokens (fcm_token)",
    "CREATE INDEX IF NOT EXISTS ix_device_tokens_user_id ON device_tokens (user_id)",
    "CREATE INDEX IF NOT EXISTS ix_device_tokens_is_active ON device_tokens (is_active)",
    "CREATE INDEX IF NOT EXISTS idx_device_tokens_user_active ON device_tokens (user_id, is_active)",
    "CREATE INDEX IF NOT EXISTS idx_device_tokens_active_last_seen ON device_tokens (is_active, last_seen_at)",
    """
    CREATE TABLE IF NOT EXISTS push_campaigns (
        id SERIAL PRIMARY KEY,
        title VARCHAR(150) NOT NULL,
        body TEXT NOT NULL,
        audience VARCHAR(20) NOT NULL DEFAULT 'all',
        target_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
        target_user_label VARCHAR(160) DEFAULT '',
        total_targeted INTEGER NOT NULL DEFAULT 0,
        firebase_accepted INTEGER NOT NULL DEFAULT 0,
        firebase_errors INTEGER NOT NULL DEFAULT 0,
        error_summary TEXT DEFAULT '',
        created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS audience VARCHAR(20) NOT NULL DEFAULT 'all'",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS target_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS target_user_label VARCHAR(160) DEFAULT ''",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS total_targeted INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS firebase_accepted INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS firebase_errors INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS error_summary TEXT DEFAULT ''",
    "ALTER TABLE push_campaigns ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP",
    "CREATE INDEX IF NOT EXISTS ix_push_campaigns_audience ON push_campaigns (audience)",
    "CREATE INDEX IF NOT EXISTS ix_push_campaigns_target_user_id ON push_campaigns (target_user_id)",
    "CREATE INDEX IF NOT EXISTS ix_push_campaigns_created_at ON push_campaigns (created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS app_settings (
        key VARCHAR(80) PRIMARY KEY,
        value VARCHAR(255) NOT NULL,
        updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
]


async def _ensure_sqlite_user_columns() -> None:
    async with engine.begin() as conn:
        cols_res = await conn.execute(text("PRAGMA table_info(users)"))
        existing_cols = {row[1] for row in cols_res.fetchall()}
        if "is_premium" not in existing_cols:
            await conn.execute(text("ALTER TABLE users ADD COLUMN is_premium BOOLEAN NOT NULL DEFAULT 0"))
        if "premium_expires_at" not in existing_cols:
            await conn.execute(text("ALTER TABLE users ADD COLUMN premium_expires_at DATETIME NULL"))
        if "last_active_date" not in existing_cols:
            await conn.execute(text("ALTER TABLE users ADD COLUMN last_active_date VARCHAR(16) DEFAULT ''"))


async def ensure_push_tables_and_schema(force: bool = False) -> None:
    """
    Garante que todas as tabelas (incluindo device_tokens e push_campaigns), colunas e índices
    existam sem apagar ou recriar a tabela users.

    Cada bloco DDL executa em transação isolada para evitar que uma instrução opcional
    cause rollback das tabelas recém-criadas no PostgreSQL.
    """
    global _schema_verified
    if _schema_verified and not force:
        return

    async with _migration_lock:
        if _schema_verified and not force:
            return

        # 1. Cria tabelas faltantes pelo ORM (checkfirst=True, nunca apaga tabelas existentes)
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync_conn: Base.metadata.create_all(sync_conn, checkfirst=True))

        # 2. Migrações idempotentes específicas por dialeto em transações separadas
        dialect = engine.dialect.name
        if dialect == "postgresql":
            for stmt in _POSTGRES_PUSH_STATEMENTS:
                async with engine.begin() as conn:
                    await conn.execute(text(stmt))
        elif dialect == "sqlite":
            await _ensure_sqlite_user_columns()

        _schema_verified = True


async def ensure_push_tables() -> None:
    """Guarda leve chamada antes de consultas de push e do painel administrativo."""
    if not _schema_verified:
        await ensure_push_tables_and_schema(force=False)


def reset_schema_cache() -> None:
    global _schema_verified
    _schema_verified = False


async def _cli_main() -> None:
    print(f"Executando migração segura no banco ({engine.dialect.name})...")
    await ensure_push_tables_and_schema(force=True)
    await engine.dispose()
    print("Migração concluída com sucesso: tabelas device_tokens e push_campaigns prontas.")


if __name__ == "__main__":
    asyncio.run(_cli_main())
