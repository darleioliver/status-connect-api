# GUIA DE DEPLOY NO RAILWAY — STATUSZAP API (status-connect-api)

Este documento orienta a conexão do repositório `status-connect-api` ao seu projeto existente no **Railway**, conectando-se diretamente ao seu banco de dados **PostgreSQL existente** via `DATABASE_URL`.

---

## 1. ESTRUTURA DO PROJETO

```
backend/
├── main.py               # Servidor FastAPI com ciclo de vida (startup tables + seeds)
├── database.py           # Conexão assíncrona SQLAlchemy (suporta DATABASE_URL do Railway)
├── models.py             # Modelos ORM (User, ContactExchange, OtpVerification, Report, AuditLog)
├── schemas.py            # Schemas Pydantic v2
├── exchange_service.py   # Algoritmo de troca recíproca e deduplicação estrita
├── admin.py              # Painel Administrativo Web (/admin/dashboard)
├── requirements.txt      # Dependências Python
├── Procfile              # Comando de inicialização com porta dinâmica ($PORT)
├── railway.json          # Configuração nativa para o Railway (Nixpacks)
└── Dockerfile            # Fallback opcional para build via Docker
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

## 3. INICIALIZAÇÃO AUTOMÁTICA DAS TABELAS

Você **NÃO** precisa rodar migrations manuais.
Ao iniciar, o evento assíncrono `lifespan` do FastAPI em `main.py` executa automaticamente:
1. `Base.metadata.create_all`: cria as tabelas `users`, `contact_exchanges`, `otp_verifications`, `reports` e `audit_logs` caso ainda não existam no seu PostgreSQL.
2. `seed_initial_community_pool`: insere os participantes verificados iniciais para que a rede já tenha contatos disponíveis para troca recíproca imediata.

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
