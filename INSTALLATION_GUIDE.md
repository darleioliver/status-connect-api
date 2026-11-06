# GUIA DE INSTALAÇÃO E HOSPEDAGEM — BACKEND STATUSZAP

Este guia detalha o processo de implantação do backend centralizado em **FastAPI**, **PostgreSQL** e **Docker** para o aplicativo Android StatusZap.

---

## 1. REQUISITOS MÍNIMOS

- **Servidor VPS / Local**: Linux (Ubuntu 22.04 LTS ou superior recomendado), macOS ou Windows com WSL2.
- **Docker e Docker Compose** instalados (método recomendado), ou **Python 3.10+** e **PostgreSQL 14+**.
- Porta **8000** (ou 80/443 com proxy reverso Nginx/Caddy) liberada no firewall.

---

## 2. INSTALAÇÃO RÁPIDA COM DOCKER (RECOMENDADO)

### Passo 1: Clonar ou transferir os arquivos para o servidor
```bash
mkdir -p /opt/statuszap/backend
cd /opt/statuszap/backend
# copie os arquivos da pasta backend deste projeto
```

### Passo 2: Subir o PostgreSQL e o FastAPI
```bash
docker compose up -d --build
```

O comando irá:
1. Criar o banco de dados PostgreSQL com persistência em volume `postgres_data`.
2. Compilar a imagem Python do FastAPI.
3. Criar as tabelas e índices automaticamente no startup.
4. Inicializar o pool de sementes da comunidade.

### Passo 3: Verificar status
```bash
docker compose ps
docker compose logs -f backend
```

Acesse no navegador:
- **Painel Administrativo**: `http://SEU_IP:8000/admin/dashboard`
- **Documentação Interativa Swagger**: `http://SEU_IP:8000/docs`
- **Healthcheck**: `http://SEU_IP:8000/api/v1/health`

---

## 3. INSTALAÇÃO MANUAL COM PYTHON (SEM DOCKER)

Caso prefira rodar diretamente no sistema com PostgreSQL local ou gerenciado (ex: AWS RDS, Supabase, Neon):

```bash
# 1. Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Configurar variável de ambiente do banco
export DATABASE_URL="postgresql+asyncpg://usuario:senha@localhost:5432/statuszap_db"
# (Ou deixe sem configurar para utilizar SQLite aiosqlite automático para testes locais)

# 4. Iniciar o servidor
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 4. CONFIGURAÇÃO DE DOMÍNIO E SSL (NGINX + CERTBOT)

Para conectar o aplicativo Android em produção com HTTPS:

```nginx
# /etc/nginx/sites-available/statuszap
server {
    server_name api.seudominio.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ative o site e gere o certificado SSL gratuito com Let's Encrypt:
```bash
sudo ln -s /etc/nginx/sites-available/statuszap /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.seudominio.com
```

---

## 5. CONECTANDO O APLICATIVO ANDROID AO SEU SERVIDOR

No aplicativo Android:
1. Abra as **Configurações de Privacidade & Conexão** no app.
2. Na seção **Servidor Central**, digite a URL da sua API:
   - Para emulador Android conectando ao localhost do PC: `http://10.0.2.2:8000`
   - Para VPS / Produção: `https://api.seudominio.com`
3. Toque em **"Testar Conexão"**. O app confirmará o status e passará a sincronizar em tempo real com seu PostgreSQL!
