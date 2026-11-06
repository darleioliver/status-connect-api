# Status Connect API (teste inicial)

API Python (FastAPI) para testar o deploy no Railway e a conexao com PostgreSQL.

> **Importante:** este projeto e apenas o teste inicial do servidor. Ainda nao possui cadastro, autenticacao, importacao ou compartilhamento de contatos.

## Arquivos

- `main.py`: API com as rotas `/` e `/testar-banco`.
- `requirements.txt`: bibliotecas Python.
- `railway.json`: configuracao de build e inicializacao no Railway.
- `Procfile`: alternativa de comando de inicializacao.
- `.gitignore`: evita enviar credenciais e ambientes locais ao GitHub.

## Como enviar ao GitHub

1. Abra seu repositorio privado `status-connect-api` no GitHub.
2. Use **Add file > Upload files** para enviar os arquivos deste pacote (na **raiz** do repositorio, e nao dentro da pasta `status-connect-api`).
3. Clique em **Commit changes**.
4. No Railway, abra seu projeto e o servico `status-connect-api` conectado ao GitHub. Um novo deploy normalmente comeca apos o commit.

## Variavel no Railway

No servico da **API** (`status-connect-api`) em **Variables**, defina:

- **Nome:** `DATABASE_URL`
- **Valor:** `${{Postgres.DATABASE_URL}}`

O nome `Postgres` na referencia deve corresponder exatamente ao nome do seu servico PostgreSQL. **Nao use** a URL do banco no codigo nem envie sua senha ao GitHub.

## Como testar

1. No servico `status-connect-api`, gere um dominio publico em **Settings > Networking**, se ainda nao tiver um.
2. Acesse `https://SEU-DOMINIO.up.railway.app/` para verificar a API.
3. Acesse `https://SEU-DOMINIO.up.railway.app/testar-banco` para testar a conexao ao PostgreSQL.

Caso o deploy falhe, abra **Deployments > Build Logs** e **Deploy Logs** no Railway para encontrar o erro exato. A URL privada do banco so funciona entre servicos conectados pela rede privada do Railway.

## Rodar no computador (opcional)

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

A API local abre em `http://127.0.0.1:8000/`. Para testar banco localmente, configure `DATABASE_URL` no ambiente antes de iniciar a API.
