# GUIA DE DEPLOY NO RAILWAY — STATUSZAP API (status-connect-api)

Este documento orienta a conexão do repositório `status-connect-api` ao seu projeto existente no **Railway**, conectando-se diretamente ao seu banco de dados **PostgreSQL existente** via `DATABASE_URL`.

---

## 1. ESTRUTURA DO PROJETO

```
backend/
├── main.py                        # Servidor FastAPI com ciclo de vida (startup tables + seeds)
├── database.py                    # Conexão assíncrona SQLAlchemy (suporta DATABASE_URL do Railway)
├── db_migrations.py               # Migração automática segura e idempotente (isolada por transação)
├── migrations/
│   └── 001_add_push_tables.sql    # SQL idempotente para PostgreSQL (device_tokens e push_campaigns)
├── models.py                      # Modelos ORM (User, ContactExchange, DeviceToken, PushCampaign, etc.)
├── schemas.py                     # Schemas Pydantic v2
├── exchange_service.py            # Algoritmo de troca recíproca e deduplicação estrita
├── push_service.py                # Integração Firebase Admin SDK (FCM)
├── admin.py                       # Painel Administrativo Web (/admin/dashboard)
├── requirements.txt               # Dependências Python (inclui sqlalchemy[asyncio], greenlet e firebase-admin)
├── Procfile                       # Comando de inicialização com porta dinâmica ($PORT)
├── railway.json                   # Configuração nativa para o Railway (Nixpacks)
└── Dockerfile                     # Fallback opcional para build via Docker
```

---

## 2. CONECTANDO AO RAILWAY E AO POSTGRESQL EXISTENTE

### Passo 1: Subir o código no repositório GitHub
No repositório `status-connect-api`:
1. Faça o commit e push dos arquivos desta pasta `backend/` na raiz do repositório `status-connect-api` (ou configure o *Root Directory* no Railway como `/backend`).

### Passo 2: Criar o Serviço no Railway
1. Abra o painel do seu projeto no [Railway](https://railway.app/).
2. Você já possui o serviço **PostgreSQL** ativo neste projeto.
3. Clique em **+ New** -> **GitHub Repo** -> selecione `status-connect-api`.
4. O Railway iniciará a detecção do projeto (via `Procfile` ou `railway.json`).

### Passo 3: Configurar a Variável de Conexão `DATABASE_URL`
Como o PostgreSQL já existe no seu projeto Railway:
1. Clique no card do serviço `status-connect-api` recém-criado.
2. Acesse a aba **Variables**.
3. Adicione a variável `DATABASE_URL`:
   * **Método 1 (Recomendado - Variable Reference)**:
     Clique em **Add Reference** e selecione a variável `DATABASE_URL` do seu serviço PostgreSQL existente. O Railway preencherá automaticamente como `${{Postgres.DATABASE_URL}}`.
   * **Método 2 (Manual)**:
     Copie o valor de `DATABASE_URL` da aba *Variables* ou *Connect* do seu PostgreSQL existente e cole no serviço da API.

> **Nota técnica**: O `database.py` já possui conversão automática: caso o Railway entregue a URL com prefixo `postgres://` ou `postgresql://`, o código converte transparentemente para o driver assíncrono `postgresql+asyncpg://`.

### Passo 4: Gerar o Domínio Público no Railway
1. No serviço `status-connect-api`, acesse a aba **Settings**.
2. Na seção **Networking**, clique em **Generate Domain** (ex: `status-connect-api-production.up.railway.app`).

---

## 3. MIGRAÇÃO SEGURA E INICIALIZAÇÃO DAS TABELAS

Ao iniciar, o evento `lifespan` de `main.py` (e a guarda pré-consulta nas rotas `/admin/*` e `/api/v1/devices/fcm-token`) chama `ensure_push_tables_and_schema()`, criando `device_tokens` e `push_campaigns` com `CREATE TABLE IF NOT EXISTS` e índices em transações isoladas **sem apagar nem recriar a tabela `users`**.

Caso queira executar manualmente no PostgreSQL do Railway:
1. **Via SQL direto (Query / psql do Railway)**: execute o arquivo `migrations/001_add_push_tables.sql`.
2. **Via Railway CLI no serviço da API**: `railway run python db_migrations.py`.

Em seguida, `seed_initial_community_pool` garante os participantes iniciais caso o banco esteja vazio.

---

## 4. VERIFICAÇÃO E PAINEL ADMINISTRATIVO

Após o deploy no Railway:
* **Healthcheck**: `https://SEU_DOMINIO_RAILWAY.up.railway.app/api/v1/health`
* **Swagger API Docs**: `https://SEU_DOMINIO_RAILWAY.up.railway.app/docs`
* **Painel Administrativo Web**: `https://SEU_DOMINIO_RAILWAY.up.railway.app/admin/dashboard`

---

## 5. CONECTANDO O APLICATIVO ANDROID

Com a URL gerada pelo Railway:
1. Abra o app **StatusZap** no celular ou emulador Android.
2. Acesse a aba **Ajustes**.
3. No campo **URL da API FastAPI**, insira:
   ```
   https://SEU_DOMINIO_RAILWAY.up.railway.app
   ```
4. Toque em **Testar Conexão**. O aplicativo confirmará o status `200 OK` e passará a sincronizar diretamente com o seu PostgreSQL no Railway!
