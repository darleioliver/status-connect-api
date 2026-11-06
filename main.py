"""API inicial do Status Connect.

Esta versão serve para verificar o deploy no Railway e a conexão com o PostgreSQL.
Ainda não implementa cadastro, autenticação ou troca de contatos.
"""

import logging
import os

from fastapi import FastAPI
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Status Connect API",
    description="API inicial para verificar a implantação no Railway e o PostgreSQL.",
    version="0.1.0",
)


@app.get("/")
def inicio():
    return {
        "status": "online",
        "aplicativo": "Status Connect",
        "mensagem": "API funcionando!",
    }


@app.get("/testar-banco")
def testar_banco():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        return {
            "status": "erro",
            "mensagem": "DATABASE_URL nao configurada no servico da API.",
        }

    engine = None
    try:
        engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5},
        )
        with engine.connect() as conexao:
            conexao.execute(text("SELECT 1"))
        return {"status": "sucesso", "mensagem": "PostgreSQL conectado!"}
    except (SQLAlchemyError, OSError, ValueError):
        # Nao exponha credenciais nem detalhes internos ao usuario da API.
        logger.exception("Falha ao conectar ao PostgreSQL")
        return {
            "status": "erro",
            "mensagem": "Nao foi possivel conectar ao PostgreSQL. Confira o DATABASE_URL nos Variables do Railway e os logs do servico.",
        }
    finally:
        if engine is not None:
            engine.dispose()
