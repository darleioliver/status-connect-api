import datetime
import hmac
import os
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from db_migrations import ensure_push_tables
from models import User, ContactExchange, Report, AuditLog, DeviceToken, PushCampaign
from schemas import PushSendRequest
from exchange_service import pause_expired_free_users
from push_service import ensure_firebase_initialized, get_audience_counts, send_push_campaign

router = APIRouter(prefix="/admin", tags=["Administração"])


def verify_admin_push_secret(x_admin_secret: str = Header(default="")):
    expected = os.getenv("ADMIN_PUSH_SECRET", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Variável ADMIN_PUSH_SECRET não configurada no Railway. Defina uma senha de administrador nas variáveis do servidor."
        )
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret.strip(), expected):
        raise HTTPException(
            status_code=401,
            detail="Senha de administrador inválida."
        )


@router.get("/metrics")
async def get_admin_metrics(db: AsyncSession = Depends(get_db)):
    await pause_expired_free_users(db)
    total_users = (await db.execute(select(func.count(User.id)))).scalar() or 0
    active_users = (await db.execute(select(func.count(User.id)).where(User.is_active == True, User.is_paused == False))).scalar() or 0
    premium_users = (await db.execute(select(func.count(User.id)).where(User.is_active == True, User.is_premium == True))).scalar() or 0
    total_exchanges = (await db.execute(select(func.count(ContactExchange.id)))).scalar() or 0
    
    # Exchanged today
    today_start = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_exchanges = (await db.execute(select(func.count(ContactExchange.id)).where(ContactExchange.distributed_at >= today_start))).scalar() or 0
    
    pending_reports = (await db.execute(select(func.count(Report.id)).where(Report.status == "pending"))).scalar() or 0
    avg_reciprocity = (await db.execute(select(func.avg(User.reciprocity_score)).where(User.is_active == True))).scalar() or 1.0

    return {
        "total_users": total_users,
        "active_users": active_users,
        "premium_users": premium_users,
        "total_exchanges": total_exchanges,
        "today_exchanges": today_exchanges,
        "pending_reports": pending_reports,
        "avg_reciprocity": round(float(avg_reciprocity), 2)
    }

@router.get("/users")
async def list_admin_users(
    search: str = Query(default=""),
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    await pause_expired_free_users(db)
    query = select(User)
    if search:
        query = query.where(User.name.ilike(f"%{search}%") | User.phone_e164.ilike(f"%{search}%"))
    query = query.order_by(desc(User.is_premium), desc(User.created_at)).offset(offset).limit(limit)
    res = await db.execute(query)
    users = res.scalars().all()

    user_ids = [u.id for u in users]
    token_counts = {}
    if user_ids:
        try:
            async with db.begin_nested():
                tok_stmt = (
                    select(DeviceToken.user_id, func.count(DeviceToken.id))
                    .where(DeviceToken.is_active == True, DeviceToken.user_id.in_(user_ids))
                    .group_by(DeviceToken.user_id)
                )
                for uid, cnt in (await db.execute(tok_stmt)).all():
                    if uid is not None:
                        token_counts[uid] = int(cnt)
        except Exception:
            # Continua listando os usuários normalmente mesmo sem registros/tabela de token FCM
            token_counts = {}
    
    return [
        {
            "id": u.id,
            "name": u.name,
            "phone_e164": u.phone_e164,
            "country_code": u.country_code,
            "bio": u.bio,
            "state": u.state or "",
            "gender": u.gender or "",
            "is_active": u.is_active,
            "is_paused": u.is_paused,
            "is_premium": bool(u.is_premium),
            "has_fcm_token": token_counts.get(u.id, 0) > 0,
            "fcm_token_count": token_counts.get(u.id, 0),
            "total_received": u.total_contacts_received,
            "total_shared": u.total_contacts_shared,
            "reciprocity_score": float(u.reciprocity_score if u.reciprocity_score is not None else 1.0),
            "created_at": u.created_at.isoformat() if u.created_at else ""
        }
        for u in users
    ]

@router.post("/users/{user_id}/toggle-premium")
async def toggle_user_premium(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_premium = not bool(user.is_premium)
    if user.is_premium:
        user.is_paused = False
    audit = AuditLog(
        user_id=user.id,
        action="PREMIUM_GRANTED" if user.is_premium else "PREMIUM_REVOKED",
        timestamp=datetime.datetime.utcnow(),
        details=f"Administrador alterou o plano de {user.name} para {'Premium' if user.is_premium else 'Grátis'}."
    )
    db.add(audit)
    await db.commit()
    return {
        "is_premium": user.is_premium,
        "message": f"Usuário agora é {'★ Premium' if user.is_premium else 'Grátis'}!"
    }

@router.post("/users/{user_id}/toggle-pause")
async def toggle_user_pause(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_paused = not user.is_paused
    await db.commit()
    return {"message": f"Usuário {'pausado' if user.is_paused else 'reativado'} com sucesso."}

@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_active = not user.is_active
    await db.commit()
    return {"message": f"Status do usuário alterado para {'ativo' if user.is_active else 'bloqueado'}."}

# --- Notificações Push (Protegido por ADMIN_PUSH_SECRET) ---

@router.get("/push/summary", dependencies=[Depends(verify_admin_push_secret)])
async def get_push_summary(db: AsyncSession = Depends(get_db)):
    await ensure_push_tables()
    counts = await get_audience_counts(db)
    firebase_ok, firebase_err = ensure_firebase_initialized()
    return {
        "audience_counts": counts,
        "firebase_configured": firebase_ok,
        "firebase_error": firebase_err or ""
    }

@router.get("/push/history", dependencies=[Depends(verify_admin_push_secret)])
async def get_push_history(
    limit: int = 30,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    stmt = select(PushCampaign).order_by(desc(PushCampaign.created_at)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": row.id,
            "title": row.title,
            "body": row.body,
            "audience": row.audience,
            "target_user_id": row.target_user_id,
            "target_user_label": row.target_user_label or "",
            "total_targeted": row.total_targeted,
            "firebase_accepted": row.firebase_accepted,
            "firebase_errors": row.firebase_errors,
            "error_summary": row.error_summary or "",
            "created_at": row.created_at.isoformat() if row.created_at else ""
        }
        for row in rows
    ]

@router.post("/push/test", dependencies=[Depends(verify_admin_push_secret)])
async def send_test_push(
    payload: PushSendRequest,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    if not payload.target_user_id:
        raise HTTPException(status_code=400, detail="Selecione um usuário para enviar a notificação de teste.")
    try:
        result = await send_push_campaign(
            db=db,
            title=payload.title,
            body=payload.body,
            audience="test",
            target_user_id=payload.target_user_id
        )
        return result
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@router.post("/push/send", dependencies=[Depends(verify_admin_push_secret)])
async def send_bulk_push(
    payload: PushSendRequest,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    audience = payload.audience if payload.audience in {"all", "free", "premium"} else "all"
    try:
        result = await send_push_campaign(
            db=db,
            title=payload.title,
            body=payload.body,
            audience=audience,
            target_user_id=None
        )
        return result
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@router.get("/reports")
async def list_reports(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Report).order_by(desc(Report.created_at)).limit(50))
    reports = res.scalars().all()
    return [
        {
            "id": r.id,
            "reporter_user_id": r.reporter_user_id,
            "reported_user_id": r.reported_user_id,
            "reason": r.reason,
            "details": r.details,
            "status": r.status,
            "created_at": r.created_at.isoformat()
        }
        for r in reports
    ]

@router.post("/reports/{report_id}/resolve")
async def resolve_report(report_id: int, action: str = "resolve", db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Denúncia não encontrada.")
    report.status = "resolved"
    if action == "ban":
        reported_user = await db.get(User, report.reported_user_id)
        if reported_user:
            reported_user.is_active = False
    await db.commit()
    return {"message": "Denúncia processada."}

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard():
    # Painel administrativo visual completo e responsivo integrado na FastAPI
    return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Administrativo — StatusZap</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <!-- Navbar -->
    <header class="bg-emerald-950 border-b border-emerald-800/50 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-emerald-500 flex items-center justify-center font-bold text-slate-900 text-xl shadow-lg shadow-emerald-500/20">
                SZ
            </div>
            <div>
                <h1 class="text-xl font-bold tracking-tight text-white">StatusZap — Painel Administrativo</h1>
                <p class="text-xs text-emerald-400">Controle de Troca Recíproca, Notificações Push & Conformidade LGPD</p>
            </div>
        </div>
        <div class="flex items-center gap-3">
            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                Servidor Conectado
            </span>
            <a href="/docs" target="_blank" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                API Docs (Swagger)
            </a>
        </div>
    </header>

    <main class="max-w-7xl mx-auto p-6 space-y-8">
        <!-- Cards de Métricas -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
            <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-5 shadow-sm">
                <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Total de Usuários</p>
                <p id="totalUsers" class="text-3xl font-bold text-white mt-2">--</p>
                <p id="activeUsersRatio" class="text-xs text-emerald-400 mt-1">Carregando...</p>
            </div>
            <div class="bg-slate-800/80 border border-amber-500/40 rounded-2xl p-5 shadow-sm">
                <p class="text-xs font-medium text-amber-400 uppercase tracking-wider">★ Assinantes Premium</p>
                <p id="premiumUsers" class="text-3xl font-bold text-amber-300 mt-2">--</p>
                <p class="text-xs text-slate-400 mt-1">Ativos 24h com filtros</p>
            </div>
            <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-5 shadow-sm">
                <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Trocas Realizadas Hoje</p>
                <p id="todayExchanges" class="text-3xl font-bold text-emerald-400 mt-2">--</p>
                <p id="totalExchanges" class="text-xs text-slate-400 mt-1">Total geral: --</p>
            </div>
            <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-5 shadow-sm">
                <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Índice de Reciprocidade</p>
                <p id="avgReciprocity" class="text-3xl font-bold text-sky-400 mt-2">--</p>
                <p class="text-xs text-slate-400 mt-1">Meta do algoritmo: 1.0 (Equilíbrio)</p>
            </div>
            <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-5 shadow-sm">
                <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Denúncias Pendentes</p>
                <p id="pendingReports" class="text-3xl font-bold text-amber-400 mt-2">--</p>
                <p class="text-xs text-slate-400 mt-1">Moderação de contatos abusivos</p>
            </div>
        </div>

        <!-- Seção de Notificações Push (Firebase FCM) -->
        <section class="bg-slate-800/80 border border-emerald-700/40 rounded-2xl p-6 shadow-sm space-y-6">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-700/70 pb-4">
                <div>
                    <div class="flex items-center gap-2.5">
                        <h2 class="text-lg font-semibold text-white">Notificações Push</h2>
                        <span id="fcmStatusBadge" class="text-xs px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600">
                            Autentique para carregar status FCM
                        </span>
                    </div>
                    <p class="text-sm text-slate-400 mt-0.5">Envie avisos pelo Firebase Cloud Messaging (FCM) com prévia, teste individual e histórico.</p>
                </div>

                <!-- Chave/Senha Admin para Disparo -->
                <div class="flex flex-wrap items-center gap-2">
                    <input id="adminSecretInput" type="password" placeholder="Senha Admin (ADMIN_PUSH_SECRET)"
                           class="bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 w-64">
                    <button onclick="unlockPushSection()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm rounded-xl transition">
                        Desbloquear Push
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <!-- Formulário de Disparo -->
                <div class="lg:col-span-7 space-y-4">
                    <div>
                        <div class="flex justify-between items-center mb-1">
                            <label for="pushTitleInput" class="text-xs font-semibold uppercase tracking-wider text-slate-300">Título da Notificação</label>
                            <span id="titleCounter" class="text-xs text-slate-500">0/120</span>
                        </div>
                        <input id="pushTitleInput" type="text" maxlength="120" oninput="updatePushPreview()"
                               placeholder="Ex.: Novos contatos disponíveis hoje no StatusZap!"
                               class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500">
                    </div>

                    <div>
                        <div class="flex justify-between items-center mb-1">
                            <label for="pushBodyInput" class="text-xs font-semibold uppercase tracking-wider text-slate-300">Mensagem</label>
                            <span id="bodyCounter" class="text-xs text-slate-500">0/500</span>
                        </div>
                        <textarea id="pushBodyInput" rows="3" maxlength="500" oninput="updatePushPreview()"
                                  placeholder="Escreva a mensagem que aparecerá no celular dos usuários..."
                                  class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500"></textarea>
                    </div>

                    <!-- Destinatários -->
                    <div>
                        <label class="text-xs font-semibold uppercase tracking-wider text-slate-300 block mb-2">Destinatários</label>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                            <label class="cursor-pointer bg-slate-900/80 border border-slate-700 rounded-xl p-3 flex items-center justify-between hover:border-emerald-500/60 transition">
                                <div class="flex items-center gap-2">
                                    <input type="radio" name="pushAudience" value="all" checked class="accent-emerald-500">
                                    <span class="text-sm font-medium text-white">Todos os usuários</span>
                                </div>
                                <span id="countAll" class="text-xs font-bold text-emerald-400">--</span>
                            </label>
                            <label class="cursor-pointer bg-slate-900/80 border border-slate-700 rounded-xl p-3 flex items-center justify-between hover:border-slate-500 transition">
                                <div class="flex items-center gap-2">
                                    <input type="radio" name="pushAudience" value="free" class="accent-emerald-500">
                                    <span class="text-sm font-medium text-white">Somente Grátis</span>
                                </div>
                                <span id="countFree" class="text-xs font-bold text-slate-300">--</span>
                            </label>
                            <label class="cursor-pointer bg-slate-900/80 border border-amber-500/40 rounded-xl p-3 flex items-center justify-between hover:border-amber-400 transition">
                                <div class="flex items-center gap-2">
                                    <input type="radio" name="pushAudience" value="premium" class="accent-amber-400">
                                    <span class="text-sm font-medium text-amber-300">Somente Premium</span>
                                </div>
                                <span id="countPremium" class="text-xs font-bold text-amber-300">--</span>
                            </label>
                        </div>
                    </div>

                    <!-- Teste para o próprio celular -->
                    <div class="bg-slate-900/70 border border-slate-700/80 rounded-xl p-4 space-y-3">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <span class="text-xs font-semibold uppercase tracking-wider text-sky-400">Teste Individual (Seu Celular)</span>
                            <span class="text-xs text-slate-400">Selecione seu número cadastrado com token FCM ativo</span>
                        </div>
                        <div class="flex flex-col sm:flex-row gap-2.5">
                            <select id="testUserSelect" class="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-sky-500">
                                <option value="">Carregando participantes...</option>
                            </select>
                            <button onclick="sendTestPush()" class="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold text-sm rounded-xl transition whitespace-nowrap">
                                Enviar Teste
                            </button>
                        </div>
                    </div>

                    <!-- Botão Principal Enviar Notificação -->
                    <div class="flex flex-wrap items-center justify-between gap-3 pt-1">
                        <button onclick="openBulkPushConfirm()" class="w-full sm:w-auto px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm rounded-xl shadow-lg shadow-emerald-500/20 transition">
                            Enviar Notificação
                        </button>
                        <p class="text-xs text-slate-400">Envios em massa pedem confirmação antes do disparo.</p>
                    </div>

                    <!-- Feedback após envio -->
                    <div id="pushResultBox" class="hidden rounded-xl p-4 border text-sm space-y-1.5"></div>
                </div>

                <!-- Prévia Visual no Celular -->
                <div class="lg:col-span-5 flex flex-col justify-between space-y-4">
                    <div>
                        <p class="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">Prévia no Android antes do envio</p>
                        <div class="bg-slate-950 border border-slate-700 rounded-2xl p-5 shadow-inner space-y-3">
                            <div class="flex items-center justify-between text-[11px] text-slate-500">
                                <span>Android • Barra de Notificações</span>
                                <span>agora</span>
                            </div>
                            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-md flex items-start gap-3">
                                <div class="w-9 h-9 rounded-full bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 font-bold text-xs shrink-0">
                                    SZ
                                </div>
                                <div class="min-w-0 flex-1">
                                    <div class="flex items-center gap-2">
                                        <span class="text-[11px] font-semibold text-emerald-400">StatusZap</span>
                                        <span class="text-[10px] text-slate-500">• agora</span>
                                    </div>
                                    <p id="previewTitle" class="text-sm font-bold text-white mt-0.5 break-words">Título da notificação</p>
                                    <p id="previewBody" class="text-xs text-slate-300 mt-1 whitespace-pre-wrap break-words">A mensagem aparecerá aqui exatamente como será exibida antes de enviar.</p>
                                </div>
                            </div>
                            <p class="text-[11px] text-slate-500">Ao tocar na notificação, o app StatusZap abre na tela inicial.</p>
                        </div>
                    </div>

                    <div class="bg-slate-900/60 border border-slate-700/70 rounded-xl p-3.5 text-xs text-slate-400 space-y-1">
                        <p class="font-semibold text-slate-200">Sobre métricas do Firebase (FCM):</p>
                        <p>O painel contabiliza quantos aparelhos tiveram a solicitação <strong>aceita pelo Firebase</strong> e quantos retornaram <strong>erro</strong>. Aceitação pelo Firebase não garante que o aparelho esteja conectado ou que o usuário abriu a notificação.</p>
                    </div>
                </div>
            </div>

            <!-- Histórico de Envios -->
            <div class="border-t border-slate-700/70 pt-5 space-y-3">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-semibold text-white uppercase tracking-wider">Histórico de Envios Push</h3>
                    <button onclick="loadPushHistory()" class="text-xs px-3 py-1 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition">
                        Atualizar Histórico
                    </button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-slate-900/60 uppercase text-slate-400 border-b border-slate-700">
                            <tr>
                                <th class="py-2.5 px-3">Data / Hora</th>
                                <th class="py-2.5 px-3">Notificação</th>
                                <th class="py-2.5 px-3">Público</th>
                                <th class="py-2.5 px-3">Dispositivos Alvo</th>
                                <th class="py-2.5 px-3">Aceitos Firebase</th>
                                <th class="py-2.5 px-3">Erros</th>
                                <th class="py-2.5 px-3">Observação</th>
                            </tr>
                        </thead>
                        <tbody id="pushHistoryBody" class="divide-y divide-slate-700/60">
                            <tr>
                                <td colspan="7" class="text-center py-5 text-slate-500">Informe a senha admin acima e clique em "Desbloquear Push" para ver o histórico.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Seção de Gerenciamento de Usuários -->
        <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-6 shadow-sm">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-lg font-semibold text-white">Participantes da Rede</h2>
                    <p class="text-sm text-slate-400">Gerencie usuários, planos Premium/Grátis, tokens push e status de compartilhamento</p>
                </div>
                <div class="flex items-center gap-3">
                    <input id="searchInput" type="text" placeholder="Buscar por nome ou WhatsApp..." 
                           class="bg-slate-900 border border-slate-700 rounded-xl px-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 w-64 sm:w-80">
                    <button onclick="loadUsers()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm rounded-xl transition">
                        Buscar
                    </button>
                </div>
            </div>

            <!-- Tabela -->
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="py-3 px-4">Usuário</th>
                            <th class="py-3 px-4">WhatsApp (E.164)</th>
                            <th class="py-3 px-4">UF / Sexo</th>
                            <th class="py-3 px-4">Plano</th>
                            <th class="py-3 px-4">Reciprocidade</th>
                            <th class="py-3 px-4">Status</th>
                            <th class="py-3 px-4 text-right">Ações</th>
                        </tr>
                    </thead>
                    <tbody id="userTableBody" class="divide-y divide-slate-700/60">
                        <tr>
                            <td colspan="7" class="text-center py-6 text-slate-500">Carregando participantes...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <!-- Modal de Confirmação para Envio em Massa -->
    <div id="confirmPushModal" class="hidden fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 class="text-lg font-bold text-white">Confirmar Envio em Massa</h3>
            <p class="text-sm text-slate-300">Confira os detalhes antes de disparar para os aparelhos via Firebase:</p>
            <div class="bg-slate-900 border border-slate-700 rounded-xl p-4 space-y-2 text-sm">
                <p><span class="text-slate-400">Público:</span> <strong id="confirmAudienceLabel" class="text-emerald-400">--</strong></p>
                <p><span class="text-slate-400">Dispositivos com token ativo:</span> <strong id="confirmAudienceCount" class="text-white">--</strong></p>
                <p><span class="text-slate-400">Título:</span> <strong id="confirmPushTitle" class="text-white">--</strong></p>
                <p><span class="text-slate-400">Mensagem:</span> <span id="confirmPushBody" class="text-slate-300">--</span></p>
            </div>
            <div class="flex justify-end gap-2.5 pt-2">
                <button onclick="closeBulkPushConfirm()" class="px-4 py-2 rounded-xl bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-medium transition">
                    Cancelar
                </button>
                <button id="confirmSendBtn" onclick="confirmBulkPushSend()" class="px-5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-sm font-bold transition">
                    Confirmar e Enviar
                </button>
            </div>
        </div>
    </div>

    <script>
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text == null ? '' : String(text);
            return div.innerHTML;
        }

        function getAdminSecret() {
            const inputVal = (document.getElementById('adminSecretInput').value || '').trim();
            if (inputVal) return inputVal;
            return (sessionStorage.getItem('statuszap_admin_push_secret') || '').trim();
        }

        function saveAdminSecret(secret) {
            if (secret) {
                sessionStorage.setItem('statuszap_admin_push_secret', secret);
            }
        }

        function updatePushPreview() {
            const title = document.getElementById('pushTitleInput').value;
            const body = document.getElementById('pushBodyInput').value;
            document.getElementById('titleCounter').textContent = `${title.length}/120`;
            document.getElementById('bodyCounter').textContent = `${body.length}/500`;
            document.getElementById('previewTitle').textContent = title.trim() || 'Título da notificação';
            document.getElementById('previewBody').textContent = body.trim() || 'A mensagem aparecerá aqui exatamente como será exibida antes de enviar.';
        }

        function showPushResult(isOk, htmlMessage) {
            const box = document.getElementById('pushResultBox');
            box.classList.remove('hidden', 'bg-emerald-950/60', 'border-emerald-600/50', 'text-emerald-200', 'bg-rose-950/60', 'border-rose-600/50', 'text-rose-200');
            if (isOk) {
                box.classList.add('bg-emerald-950/60', 'border-emerald-600/50', 'text-emerald-200');
            } else {
                box.classList.add('bg-rose-950/60', 'border-rose-600/50', 'text-rose-200');
            }
            box.innerHTML = htmlMessage;
        }

        function audienceLabel(aud) {
            if (aud === 'premium') return 'Somente usuários Premium';
            if (aud === 'free') return 'Somente usuários Grátis';
            if (aud === 'test') return 'Teste individual';
            return 'Todos os usuários';
        }

        async function unlockPushSection() {
            const secret = getAdminSecret();
            if (!secret) {
                showPushResult(false, '<strong>Informe a senha de administrador</strong> (variável ADMIN_PUSH_SECRET no Railway).');
                return;
            }
            saveAdminSecret(secret);
            await loadPushSummary();
            await loadPushHistory();
        }

        async function loadPushSummary() {
            const secret = getAdminSecret();
            const badge = document.getElementById('fcmStatusBadge');
            if (!secret) return;
            try {
                const res = await fetch('/admin/push/summary', {
                    headers: { 'X-Admin-Secret': secret }
                });
                const data = await res.json();
                if (!res.ok) {
                    badge.textContent = data.detail || 'Senha admin inválida';
                    badge.className = 'text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40';
                    return;
                }
                const counts = data.audience_counts || {};
                document.getElementById('countAll').textContent = counts.all ?? 0;
                document.getElementById('countFree').textContent = counts.free ?? 0;
                document.getElementById('countPremium').textContent = counts.premium ?? 0;

                if (data.firebase_configured) {
                    badge.textContent = 'Firebase Admin Conectado';
                    badge.className = 'text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
                } else {
                    badge.textContent = 'Falta FIREBASE_SERVICE_ACCOUNT_JSON no Railway';
                    badge.className = 'text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40';
                }
            } catch (e) {
                console.error('Erro ao carregar resumo FCM', e);
            }
        }

        async function loadPushHistory() {
            const secret = getAdminSecret();
            const tbody = document.getElementById('pushHistoryBody');
            if (!secret) return;
            try {
                const res = await fetch('/admin/push/history', {
                    headers: { 'X-Admin-Secret': secret }
                });
                if (!res.ok) {
                    const err = await res.json();
                    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-5 text-rose-400">${escapeHtml(err.detail || 'Não autorizado')}</td></tr>`;
                    return;
                }
                const rows = await res.json();
                if (rows.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-5 text-slate-500">Nenhuma notificação enviada ainda.</td></tr>';
                    return;
                }
                tbody.innerHTML = rows.map(r => {
                    const dt = new Date(r.created_at + 'Z').toLocaleString('pt-BR');
                    const audTag = r.audience === 'premium'
                        ? '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300">Premium</span>'
                        : r.audience === 'free'
                        ? '<span class="px-2 py-0.5 rounded-full bg-slate-700 text-slate-200">Grátis</span>'
                        : r.audience === 'test'
                        ? `<span class="px-2 py-0.5 rounded-full bg-sky-500/20 text-sky-300">Teste (${escapeHtml(r.target_user_label)})</span>`
                        : '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300">Todos</span>';
                    return `
                        <tr class="hover:bg-slate-700/30 transition">
                            <td class="py-2.5 px-3 whitespace-nowrap text-slate-400">${escapeHtml(dt)}</td>
                            <td class="py-2.5 px-3 max-w-xs">
                                <div class="font-semibold text-white truncate">${escapeHtml(r.title)}</div>
                                <div class="text-slate-400 truncate">${escapeHtml(r.body)}</div>
                            </td>
                            <td class="py-2.5 px-3 whitespace-nowrap">${audTag}</td>
                            <td class="py-2.5 px-3 font-semibold text-white">${r.total_targeted}</td>
                            <td class="py-2.5 px-3 font-semibold text-emerald-400">${r.firebase_accepted}</td>
                            <td class="py-2.5 px-3 font-semibold ${r.firebase_errors > 0 ? 'text-rose-400' : 'text-slate-400'}">${r.firebase_errors}</td>
                            <td class="py-2.5 px-3 text-slate-400 max-w-xs truncate">${escapeHtml(r.error_summary || 'Solicitação enviada ao FCM')}</td>
                        </tr>
                    `;
                }).join('');
            } catch (e) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center py-5 text-rose-400">Erro ao carregar histórico.</td></tr>';
            }
        }

        function renderPushDispatchFeedback(data, isTest) {
            const kind = isTest ? 'Notificação de teste' : `Disparo (${audienceLabel(data.audience)})`;
            const errNote = data.error_summary
                ? `<p class="text-xs text-amber-300">Detalhes: ${escapeHtml(data.error_summary)}</p>`
                : '';
            showPushResult(
                true,
                `
                <p class="font-bold text-white">${escapeHtml(kind)} processado pelo Firebase</p>
                <div class="flex flex-wrap gap-4 text-xs pt-1">
                    <span>Dispositivos alvo: <strong>${data.total_targeted}</strong></span>
                    <span class="text-emerald-300">Aceitas pelo Firebase: <strong>${data.firebase_accepted}</strong></span>
                    <span class="${data.firebase_errors > 0 ? 'text-rose-300' : 'text-slate-300'}">Com erro: <strong>${data.firebase_errors}</strong></span>
                </div>
                ${errNote}
                <p class="text-[11px] text-slate-400 pt-1">Obs.: Aceitação pelo Firebase indica apenas que o servidor FCM aceitou a solicitação — não confirma entrega no aparelho nem leitura.</p>
                `
            );
        }

        async function sendTestPush() {
            const secret = getAdminSecret();
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            const targetUserId = Number(document.getElementById('testUserSelect').value || 0);

            if (!secret) {
                showPushResult(false, 'Informe a senha de administrador e clique em Desbloquear Push antes de testar.');
                return;
            }
            if (!title || !body) {
                showPushResult(false, 'Preencha o título e a mensagem da notificação antes de enviar o teste.');
                return;
            }
            if (!targetUserId) {
                showPushResult(false, 'Selecione o usuário/número do seu celular na lista de teste.');
                return;
            }
            saveAdminSecret(secret);

            try {
                const res = await fetch('/admin/push/test', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Secret': secret
                    },
                    body: JSON.stringify({
                        title,
                        body,
                        audience: 'test',
                        target_user_id: targetUserId
                    })
                });
                const data = await res.json();
                if (!res.ok) {
                    showPushResult(false, escapeHtml(data.detail || 'Falha ao enviar teste.'));
                    return;
                }
                renderPushDispatchFeedback(data, true);
                loadPushSummary();
                loadPushHistory();
            } catch (e) {
                showPushResult(false, 'Erro de rede ao enviar notificação de teste.');
            }
        }

        function openBulkPushConfirm() {
            const secret = getAdminSecret();
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            if (!secret) {
                showPushResult(false, 'Informe a senha de administrador e clique em Desbloquear Push antes de enviar.');
                return;
            }
            if (!title || !body) {
                showPushResult(false, 'Preencha o título e a mensagem antes de enviar.');
                return;
            }
            const aud = document.querySelector('input[name="pushAudience"]:checked').value;
            const countMap = {
                all: document.getElementById('countAll').textContent,
                free: document.getElementById('countFree').textContent,
                premium: document.getElementById('countPremium').textContent
            };
            document.getElementById('confirmAudienceLabel').textContent = audienceLabel(aud);
            document.getElementById('confirmAudienceCount').textContent = countMap[aud] || '--';
            document.getElementById('confirmPushTitle').textContent = title;
            document.getElementById('confirmPushBody').textContent = body;
            document.getElementById('confirmPushModal').classList.remove('hidden');
        }

        function closeBulkPushConfirm() {
            document.getElementById('confirmPushModal').classList.add('hidden');
        }

        async function confirmBulkPushSend() {
            const secret = getAdminSecret();
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            const aud = document.querySelector('input[name="pushAudience"]:checked').value;
            const btn = document.getElementById('confirmSendBtn');
            btn.disabled = true;
            btn.textContent = 'Enviando...';
            saveAdminSecret(secret);

            try {
                const res = await fetch('/admin/push/send', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Secret': secret
                    },
                    body: JSON.stringify({ title, body, audience: aud })
                });
                const data = await res.json();
                closeBulkPushConfirm();
                if (!res.ok) {
                    showPushResult(false, escapeHtml(data.detail || 'Erro ao enviar notificações.'));
                } else {
                    renderPushDispatchFeedback(data, false);
                    loadPushSummary();
                    loadPushHistory();
                }
            } catch (e) {
                closeBulkPushConfirm();
                showPushResult(false, 'Erro de rede ao disparar notificações em massa.');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Confirmar e Enviar';
            }
        }

        async function loadMetrics() {
            try {
                const res = await fetch('/admin/metrics');
                const data = await res.json();
                document.getElementById('totalUsers').textContent = data.total_users;
                document.getElementById('activeUsersRatio').textContent = `${data.active_users} ativos na rede`;
                document.getElementById('premiumUsers').textContent = data.premium_users || 0;
                document.getElementById('todayExchanges').textContent = data.today_exchanges;
                document.getElementById('totalExchanges').textContent = `Total geral: ${data.total_exchanges}`;
                document.getElementById('avgReciprocity').textContent = data.avg_reciprocity.toFixed(2);
                document.getElementById('pendingReports').textContent = data.pending_reports;
            } catch(e) {
                console.error("Erro ao carregar métricas", e);
            }
        }

        function populateTestUserSelect(users) {
            const selectEl = document.getElementById('testUserSelect');
            const currentVal = selectEl.value;
            const sorted = [...users].sort((a, b) => (b.has_fcm_token ? 1 : 0) - (a.has_fcm_token ? 1 : 0));
            const options = ['<option value="">Selecione um usuário para teste...</option>'];
            sorted.forEach(u => {
                const tokenTag = u.has_fcm_token ? '📱 Push Ativo' : 'Sem token FCM';
                const planTag = u.is_premium ? '★ Premium' : 'Grátis';
                options.push(`<option value="${u.id}">${escapeHtml(u.name)} — ${escapeHtml(u.phone_e164)} (${planTag} • ${tokenTag})</option>`);
            });
            selectEl.innerHTML = options.join('');
            if (currentVal) selectEl.value = currentVal;
        }

        async function loadUsers() {
            const search = document.getElementById('searchInput').value;
            const tbody = document.getElementById('userTableBody');
            try {
                const res = await fetch(`/admin/users?search=${encodeURIComponent(search)}`);
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                const users = await res.json();
                if (!Array.isArray(users)) {
                    throw new Error('Resposta inválida ao listar usuários');
                }
                if (!search) {
                    populateTestUserSelect(users);
                }
                if (users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-slate-500">Nenhum participante encontrado.</td></tr>';
                    return;
                }
                tbody.innerHTML = users.map(u => {
                    const userName = u.name || 'Participante';
                    const score = Number(u.reciprocity_score ?? 1.0).toFixed(2);
                    const tokenBadge = u.has_fcm_token
                        ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">📱 Push</span>'
                        : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/80 text-slate-400 border border-slate-600/60">Sem token</span>';
                    return `
                    <tr class="hover:bg-slate-700/30 transition ${u.is_premium ? 'bg-amber-500/5' : ''}">
                        <td class="py-3 px-4 font-medium text-white flex items-center gap-2">
                            <span class="w-7 h-7 rounded-full ${u.is_premium ? 'bg-amber-500/20 text-amber-300 border-amber-500' : 'bg-emerald-950 text-emerald-400 border-emerald-700'} border flex items-center justify-center text-xs font-bold">
                                ${u.is_premium ? '★' : escapeHtml(userName.charAt(0).toUpperCase())}
                            </span>
                            <div>
                                <div class="flex items-center gap-1.5">
                                    <span>${escapeHtml(userName)}</span>
                                    ${tokenBadge}
                                </div>
                                <div class="text-xs text-slate-400 truncate max-w-[160px]">${escapeHtml(u.bio || 'Status do WhatsApp')}</div>
                            </div>
                        </td>
                        <td class="py-3 px-4 text-emerald-400 font-mono text-xs">${escapeHtml(u.phone_e164)}</td>
                        <td class="py-3 px-4 text-xs text-slate-300">${escapeHtml(u.state || '--')} • ${escapeHtml(u.gender || '--')}</td>
                        <td class="py-3 px-4">
                            ${u.is_premium
                                ? '<span class="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50">★ PREMIUM</span>'
                                : '<span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300">Grátis</span>'}
                        </td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-0.5 rounded text-xs font-semibold ${Number(score) >= 1.0 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'}">
                                ${score}
                            </span>
                        </td>
                        <td class="py-3 px-4">
                            ${!u.is_active ? '<span class="text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">Bloqueado</span>' :
                              u.is_paused ? '<span class="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">Pausado</span>' :
                              '<span class="text-xs px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">Ativo</span>'}
                        </td>
                        <td class="py-3 px-4 text-right space-x-1.5 whitespace-nowrap">
                            <button onclick="togglePremium(${u.id})" class="text-xs px-2.5 py-1 rounded font-semibold ${u.is_premium ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40' : 'bg-amber-600 hover:bg-amber-500 text-slate-950'} transition">
                                ${u.is_premium ? 'Remover Premium' : '★ Tornar Premium'}
                            </button>
                            <button onclick="togglePause(${u.id})" class="text-xs px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 transition">
                                ${u.is_paused ? 'Reativar' : 'Pausar'}
                            </button>
                            <button onclick="toggleActive(${u.id})" class="text-xs px-2 py-1 rounded ${u.is_active ? 'bg-rose-900/50 hover:bg-rose-900 text-rose-300' : 'bg-emerald-900/50 hover:bg-emerald-900 text-emerald-300'} transition">
                                ${u.is_active ? 'Bloquear' : 'Desbloquear'}
                            </button>
                        </td>
                    </tr>
                `;
                }).join('');
            } catch(e) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-rose-400">Erro ao buscar dados.</td></tr>';
            }
        }

        async function togglePremium(id) {
            await fetch(`/admin/users/${id}/toggle-premium`, { method: 'POST' });
            loadUsers();
            loadMetrics();
            loadPushSummary();
        }

        async function togglePause(id) {
            await fetch(`/admin/users/${id}/toggle-pause`, { method: 'POST' });
            loadUsers();
            loadMetrics();
        }

        async function toggleActive(id) {
            await fetch(`/admin/users/${id}/toggle-active`, { method: 'POST' });
            loadUsers();
            loadMetrics();
        }

        // Init
        const savedSecret = sessionStorage.getItem('statuszap_admin_push_secret') || '';
        if (savedSecret) {
            document.getElementById('adminSecretInput').value = savedSecret;
            loadPushSummary();
            loadPushHistory();
        }
        loadMetrics();
        loadUsers();
        setInterval(loadMetrics, 10000);
    </script>
</body>
</html>
    """
