# StatusZap — backend de testes no Railway

## Instalação

Envie **o conteúdo desta pasta**, não a pasta como subdiretório, para a raiz do repositório `status-connect-api` já ligado ao Railway. Não crie outro serviço nem outro PostgreSQL.

Em `status-connect-api → Variables`, mantenha `DATABASE_URL=${{Postgres.DATABASE_URL}}` e adicione `ADMIN_USER` e `ADMIN_PASSWORD` (senha forte com pelo menos 16 caracteres). Não coloque credenciais no GitHub.

Após deploy, teste `/api/v1/health`, `/docs` e `/admin/dashboard` (este último solicitará usuário e senha).

**Limitação crítica:** as rotas de usuário identificam a conta apenas por ID, sem autenticação/autorização. Isso permite consultar contatos ou alterar/excluir contas conhecendo IDs. **Não cadastre números reais nem compartilhe o APK com terceiros nesta versão de testes.** Antes de usar com usuários, implemente tokens por conta e verificação de propriedade de cada recurso, com mudanças correspondentes no Android.

O OTP `123456` permanece habilitado exclusivamente para testes; ele não comprova posse do número. O sistema original retorna também o código gerado na resposta, portanto não é adequado à produção.

A criação automática de contatos de exemplo foi desativada para evitar divulgar números potencialmente reais sem consentimento. O backend exige `DATABASE_URL` e não poderá cair silenciosamente para SQLite.

O arquivo `admin.py` ganhou proteção HTTP Basic. O dashboard carrega dados usando `fetch`, e seu navegador deverá usar as credenciais da sessão; valide isso antes de operar.

`create_all` cria tabelas ausentes, mas **não faz migrações** de tabelas existentes. Faça backup antes de atualizar versões futuras.
