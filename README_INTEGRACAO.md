# COMUNICAÇÃO ANDROID <-> FASTAPI (STATUSZAP)

Esta pasta contém o código-fonte Kotlin do aplicativo Android responsável pela comunicação com a API FastAPI no Railway.

## Arquivos:

1. **`StatusZapApiService.kt`**: Interface Retrofit contendo todos os contratos de API:
   - `POST /api/v1/otp/request` (solicitação de OTP)
   - `POST /api/v1/otp/verify` (validação de OTP)
   - `POST /api/v1/users/register` (cadastro e consentimento LGPD)
   - `GET /api/v1/users/{id}` (perfil)
   - `GET /api/v1/users/{id}/stats` (métricas de troca e reciprocidade)
   - `POST /api/v1/users/{id}/exchange` (solicitação de novo lote deduplicado)
   - `GET /api/v1/users/{id}/contacts` (histórico de contatos recebidos)
   - `POST /api/v1/users/{id}/contacts/mark-added` (marca contatos como salvos na agenda)
   - `POST /api/v1/users/{id}/privacy` (pausa ou reativação do número)
   - `DELETE /api/v1/users/{id}` (exclusão definitiva de conta sob LGPD)
   - `POST /api/v1/reports` (denúncia e moderação)
   - `GET /api/v1/health` (health check e teste de conectividade)

2. **`ApiModels.kt`**: Modelos de requisição e resposta Moshi com mapeamento snake_case (`@Json(name = "phone_e164")`) para propriedades camelCase no Kotlin.

3. **`ApiClient.kt`**: Cliente HTTP OkHttpClient + Retrofit com suporte a alteração dinâmica de URL base em tempo de execução (permite ao usuário inserir a URL do Railway diretamente na tela de Ajustes do aplicativo).

4. **`StatusZapRepository.kt`**: Camada de repositório que faz a ponte entre o banco de dados Room local (SQLite) e a API remota FastAPI.

5. **`ContactsHelper.kt`**: Utilitário nativo do Android para inserção de contatos via `ContactsContract`, exportação universal em arquivo `vCard 3.0 (.vcf)` e abertura de conversa direta no WhatsApp via `https://wa.me/`.
