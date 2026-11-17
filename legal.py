from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["Legal & Google Play"])

_LEGAL_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Política de Privacidade e Termos de Uso — StatusZap</title>
  <meta name="description" content="Política de Privacidade, Conformidade LGPD, Exclusão de Dados e Termos de Uso do aplicativo StatusZap (com.aistudio.statuszap.trkd)." />
  <style>
    :root {
      --bg: #0b141a;
      --surface: #111b21;
      --surface-alt: #18252d;
      --border: #23333d;
      --text: #e9edef;
      --muted: #9eb0ba;
      --accent: #25d366;
      --accent-dark: #128c7e;
      --gold: #f5b400;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.65;
    }
    .topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      background: rgba(17, 27, 33, 0.94);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border);
    }
    .topbar-inner {
      max-width: 920px;
      margin: 0 auto;
      padding: 14px 20px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 800;
      font-size: 1.1rem;
      letter-spacing: -0.01em;
    }
    .brand-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 9px;
      background: linear-gradient(135deg, var(--accent), var(--accent-dark));
      color: #062112;
      font-weight: 900;
    }
    .nav-links {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .nav-links a {
      color: var(--text);
      text-decoration: none;
      font-size: 0.88rem;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 999px;
      background: var(--surface-alt);
      border: 1px solid var(--border);
      transition: border-color 0.2s, color 0.2s;
    }
    .nav-links a:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .container {
      max-width: 920px;
      margin: 0 auto;
      padding: 28px 20px 64px;
    }
    .hero {
      background: linear-gradient(145deg, #111b21, #132822);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px 24px;
      margin-bottom: 24px;
    }
    .hero h1 {
      margin: 0 0 10px;
      font-size: 1.75rem;
      line-height: 1.25;
    }
    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px 18px;
      color: var(--muted);
      font-size: 0.9rem;
      margin-top: 10px;
    }
    .pill {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      background: rgba(37, 211, 102, 0.14);
      color: var(--accent);
      border: 1px solid rgba(37, 211, 102, 0.35);
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
    }
    .card h2 {
      margin: 0 0 14px;
      font-size: 1.32rem;
      color: var(--accent);
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
    }
    .card h3 {
      margin: 18px 0 8px;
      font-size: 1.03rem;
      color: #ffffff;
    }
    p {
      margin: 0 0 12px;
      color: #d6dfe4;
    }
    ul {
      margin: 6px 0 14px;
      padding-left: 20px;
      color: #d6dfe4;
    }
    li { margin-bottom: 6px; }
    .highlight-box {
      background: var(--surface-alt);
      border-left: 4px solid var(--accent);
      border-radius: 10px;
      padding: 14px 16px;
      margin: 14px 0;
    }
    .warning-box {
      background: rgba(245, 180, 0, 0.08);
      border-left: 4px solid var(--gold);
      border-radius: 10px;
      padding: 14px 16px;
      margin: 14px 0;
    }
    a.inline-link {
      color: var(--accent);
      text-decoration: underline;
    }
    footer {
      text-align: center;
      color: var(--muted);
      font-size: 0.85rem;
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }
    @media (max-width: 600px) {
      .hero h1 { font-size: 1.42rem; }
      .card { padding: 18px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-badge">SZ</span>
        <span>StatusZap</span>
      </div>
      <nav class="nav-links" aria-label="Navegação legal">
        <a href="#privacidade">Política de Privacidade</a>
        <a href="#termos">Termos de Uso</a>
        <a href="#exclusao">Exclusão de Dados</a>
        <a href="#contato">Contato</a>
      </nav>
    </div>
  </header>

  <main class="container">
    <section class="hero">
      <span class="pill">LGPD &amp; Google Play</span>
      <h1>Política de Privacidade e Termos de Uso — StatusZap</h1>
      <p>
        Este documento explica de forma transparente como o aplicativo <strong>StatusZap</strong>
        (pacote Android <code>com.aistudio.statuszap.trkd</code>) coleta, utiliza, armazena,
        compartilha e protege os dados dos usuários, bem como as regras para utilização da plataforma.
      </p>
      <div class="meta-row">
        <span><strong>Aplicativo:</strong> StatusZap</span>
        <span><strong>Última atualização:</strong> Novembro de 2026</span>
        <span><strong>Suporte:</strong> WhatsApp +55 77 9973-6034 • darleioliveira1@gmail.com</span>
      </div>
    </section>

    <section id="privacidade" class="card">
      <h2>1. Política de Privacidade</h2>

      <h3>1.1. O que é o StatusZap</h3>
      <p>
        O StatusZap é uma plataforma de troca voluntária, consentida e recíproca de contatos entre
        pessoas e criadores que desejam ampliar o alcance orgânico de seus Status no WhatsApp.
      </p>
      <div class="warning-box">
        <strong>Independência:</strong> O StatusZap não possui vínculo, patrocínio ou afiliação com
        a Meta Platforms, Inc. ou com o WhatsApp LLC. O aplicativo <strong>não</strong> lê mensagens
        privadas, <strong>não</strong> automatiza cliques ou visualizações e <strong>não</strong>
        acessa conversas do seu WhatsApp.
      </div>

      <h3>1.2. Dados Pessoais Coletados</h3>
      <p>Para operar a rede de troca recíproca com segurança e transparência, coletamos apenas:</p>
      <ul>
        <li><strong>Dados cadastrais fornecidos por você:</strong> nome de exibição, número de telefone/WhatsApp (com DDI/DDD), código do país, Estado (UF), sexo/gênero, biografia curta (descrição do perfil) e senha (armazenada exclusivamente em formato criptografado/hash).</li>
        <li><strong>Dados de uso da conta e reciprocidade:</strong> contadores de contatos recebidos/compartilhados, status da assinatura (Grátis ou Premium), histórico de pausas e registros de denúncias.</li>
        <li><strong>Identificadores técnicos para notificações Push:</strong> token do dispositivo via <em>Firebase Cloud Messaging (FCM)</em> para envio de avisos, atualizações da rede e lembretes de reativação diária quando autorizado pelo usuário.</li>
        <li><strong>Estatísticas agregadas de utilização:</strong> eventos de navegação e uso do aplicativo via <em>Google Firebase Analytics</em> (abertura de telas, cadastro, login, solicitação de lotes e acesso aos planos Premium), sem envio de números de telefone ou senhas nos eventos analíticos.</li>
        <li><strong>Registros de auditoria LGPD e segurança:</strong> data/hora do aceite dos Termos, alterações de privacidade (pausa/reativação) e solicitações de exclusão.</li>
      </ul>

      <h3>1.3. Permissões do Dispositivo Android</h3>
      <ul>
        <li><strong>Contatos (<code>READ_CONTACTS</code> / <code>WRITE_CONTACTS</code>):</strong> solicitada e utilizada apenas quando o usuário escolhe salvar ou verificar os contatos recebidos da rede na agenda do aparelho. <strong>Não coletamos, não lemos nem enviamos sua agenda particular de contatos pessoais para nossos servidores ou terceiros.</strong></li>
        <li><strong>Notificações (<code>POST_NOTIFICATIONS</code>):</strong> opcional, usada no Android 13 ou superior para exibir alertas enviados via Firebase Cloud Messaging.</li>
        <li><strong>Internet e Estado da Rede (<code>INTERNET</code>, <code>ACCESS_NETWORK_STATE</code>):</strong> necessária para sincronizar contatos da rede e validar sua conta na API.</li>
      </ul>

      <h3>1.4. Base Legal e Compartilhamento de Dados (LGPD)</h3>
      <p>
        O tratamento dos seus dados pessoais tem como base legal o seu <strong>consentimento explícito</strong>
        (Art. 7º, I da Lei nº 13.709/2018 — LGPD) e a execução dos serviços solicitados por você:
      </p>
      <ul>
        <li><strong>Compartilhamento com outros participantes ativos:</strong> ao concluir o cadastro e manter sua conta ativa (não pausada), seu nome de exibição, número de WhatsApp, bio, UF, gênero e selo (quando Premium) ficam disponíveis em lotes limitados e deduplicados para outros participantes da rede StatusZap adicionarem você na agenda.</li>
        <li><strong>Provedores de infraestrutura:</strong> utilizamos hospedagem em nuvem (Railway / PostgreSQL) para armazenamento seguro dos cadastros e Google Firebase (FCM e Analytics) para entrega de notificações e métricas de uso.</li>
        <li><strong>Pagamentos externos (Mercado Pago):</strong> ao optar por um plano Premium, você é redirecionado para o checkout oficial do Mercado Pago no navegador. O StatusZap não coleta nem armazena números de cartão de crédito ou dados bancários.</li>
        <li><strong>Não comercializamos seus dados:</strong> nunca vendemos ou alugamos suas informações pessoais a terceiros anunciantes.</li>
      </ul>

      <h3>1.5. Segurança e Retenção</h3>
      <p>
        Adotamos comunicação criptografada via HTTPS/TLS entre o aplicativo e nossa API, armazenamento
        de senhas com hash criptográfico, controle de acesso administrativo autenticado e registros
        de auditoria. Os dados são mantidos enquanto sua conta permanecer ativa ou pelo período mínimo
        exigido por obrigações legais.
      </p>
    </section>

    <section id="termos" class="card">
      <h2>2. Termos de Uso</h2>

      <h3>2.1. Elegibilidade e Aceitação</h3>
      <p>
        Ao criar uma conta ou utilizar o aplicativo StatusZap, você declara ter <strong>18 anos ou mais</strong>
        (ou autorização legal válida), concorda integralmente com estes Termos de Uso e com a Política
        de Privacidade acima e autoriza voluntariamente a disponibilização do seu número aos demais
        participantes da rede enquanto sua conta estiver ativa.
      </p>

      <h3>2.2. Funcionamento da Rede e Planos</h3>
      <ul>
        <li><strong>Modo Visitante:</strong> permite conhecer a interface antes do cadastro, sem participar da distribuição de número.</li>
        <li><strong>Plano Grátis:</strong> participa da troca recíproca de contatos com pausa automática diária às 00:00 (horário de Brasília), podendo ser reativado manualmente pelo usuário ao abrir o aplicativo.</li>
        <li><strong>Plano Premium:</strong> oferece distribuição contínua 24 horas (sem pausa automática à meia-noite), destaque visual nos contatos recebidos e filtros avançados por Sexo e Região/UF.</li>
      </ul>

      <h3>2.3. Regras de Conduta e Proibições</h3>
      <p>Para preservar a segurança e qualidade da comunidade, é estritamente proibido:</p>
      <ul>
        <li>Enviar spam em massa, mensagens não solicitadas abusivas, golpes, links maliciosos ou phishing.</li>
        <li>Publicar ou divulgar conteúdo ilegal, discriminatório, violento, fraudulento ou pornográfico.</li>
        <li>Cadastrar números de terceiros sem autorização ou utilizar ferramentas automatizadas/robôs para extrair contatos da plataforma.</li>
      </ul>
      <p>
        Qualquer usuário pode denunciar comportamentos inadequados diretamente pelo aplicativo. Contas
        que violarem estas regras poderão ser suspensas ou banidas permanentemente sem aviso prévio.
      </p>

      <h3>2.4. Isenção de Responsabilidade</h3>
      <p>
        O StatusZap atua exclusivamente como ponte voluntária de descoberta e organização de contatos
        entre interessados. Não nos responsabilizamos pelo conteúdo publicado nos Status de terceiros
        nem pelas interações ou negociações realizadas fora do aplicativo.
      </p>
    </section>

    <section id="exclusao" class="card">
      <h2>3. Controle, Pausa e Exclusão de Dados (Direitos do Titular)</h2>
      <p>
        Em conformidade com a LGPD e as diretrizes do Google Play, você possui controle total sobre seus dados:
      </p>
      <div class="highlight-box">
        <strong>Como pausar temporariamente:</strong><br />
        No aplicativo, acesse a aba <strong>Ajustes</strong> e desative a chave
        <em>"Disponibilizar Número na Rede"</em>. Seu número deixará imediatamente de ser entregue a novos participantes.
      </div>
      <div class="highlight-box">
        <strong>Como excluir sua conta definitivamente pelo aplicativo:</strong><br />
        Acesse <strong>Ajustes &rarr; LGPD &amp; Direitos do Titular &rarr; "Excluir Minha Conta e Revogar Dados"</strong>.
        Sua conta será inativada imediatamente, o consentimento será revogado e seu número não será mais distribuído na rede.
      </div>
      <p>
        Caso não tenha mais acesso ao aparelho ou deseje solicitar a remoção, confirmação ou correção
        de seus dados pessoais por atendimento direto, utilize nossos canais oficiais abaixo informando
        o número de WhatsApp cadastrado.
      </p>
    </section>

    <section id="contato" class="card">
      <h2>4. Contato e Encarregado de Dados (DPO / Suporte)</h2>
      <p>Para dúvidas sobre privacidade, solicitações LGPD, denúncias ou suporte técnico:</p>
      <ul>
        <li><strong>E-mail:</strong> <a class="inline-link" href="mailto:darleioliveira1@gmail.com">darleioliveira1@gmail.com</a></li>
        <li><strong>WhatsApp de Suporte:</strong> <a class="inline-link" href="https://wa.me/557799736034">+55 77 9973-6034</a></li>
      </ul>
    </section>

    <footer>
      StatusZap &copy; 2026 — Todos os direitos reservados.
    </footer>
  </main>
</body>
</html>
"""


@router.get("/privacidade", response_class=HTMLResponse, include_in_schema=False)
@router.get("/politica-de-privacidade", response_class=HTMLResponse, include_in_schema=False)
@router.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
@router.get("/termos", response_class=HTMLResponse, include_in_schema=False)
@router.get("/termos-de-uso", response_class=HTMLResponse, include_in_schema=False)
@router.get("/terms", response_class=HTMLResponse, include_in_schema=False)
@router.get("/exclusao-de-dados", response_class=HTMLResponse, include_in_schema=False)
async def legal_privacy_and_terms_page() -> HTMLResponse:
    return HTMLResponse(
        content=_LEGAL_HTML,
        status_code=200,
        headers={
            "Cache-Control": "public, max-age=3600",
            "X-Content-Type-Options": "nosniff",
        },
    )
