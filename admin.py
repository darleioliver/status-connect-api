import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import User, ContactExchange, Report, AuditLog
from exchange_service import pause_expired_free_users

router = APIRouter(prefix="/admin", tags=["Administração"])

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
    await pause_expired_free_users(db)
    query = select(User)
    if search:
        query = query.where(User.name.ilike(f"%{search}%") | User.phone_e164.ilike(f"%{search}%"))
    query = query.order_by(desc(User.is_premium), desc(User.created_at)).offset(offset).limit(limit)
    res = await db.execute(query)
    users = res.scalars().all()
    
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
            "total_received": u.total_contacts_received,
            "total_shared": u.total_contacts_shared,
            "reciprocity_score": u.reciprocity_score,
            "created_at": u.created_at.isoformat()
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
                <p class="text-xs text-emerald-400">Controle de Troca Recíproca & Conformidade LGPD</p>
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

        <!-- Seção de Gerenciamento de Usuários -->
        <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-6 shadow-sm">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-lg font-semibold text-white">Participantes da Rede</h2>
                    <p class="text-sm text-slate-400">Gerencie usuários, planos Premium/Grátis e status de compartilhamento</p>
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

    <script>
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

        async function loadUsers() {
            const search = document.getElementById('searchInput').value;
            const tbody = document.getElementById('userTableBody');
            try {
                const res = await fetch(`/admin/users?search=${encodeURIComponent(search)}`);
                const users = await res.json();
                if (users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-slate-500">Nenhum participante encontrado.</td></tr>';
                    return;
                }
                tbody.innerHTML = users.map(u => `
                    <tr class="hover:bg-slate-700/30 transition ${u.is_premium ? 'bg-amber-500/5' : ''}">
                        <td class="py-3 px-4 font-medium text-white flex items-center gap-2">
                            <span class="w-7 h-7 rounded-full ${u.is_premium ? 'bg-amber-500/20 text-amber-300 border-amber-500' : 'bg-emerald-950 text-emerald-400 border-emerald-700'} border flex items-center justify-center text-xs font-bold">
                                ${u.is_premium ? '★' : u.name.charAt(0).toUpperCase()}
                            </span>
                            <div>
                                <div>${u.name}</div>
                                <div class="text-xs text-slate-400 truncate max-w-[160px]">${u.bio || 'Status do WhatsApp'}</div>
                            </div>
                        </td>
                        <td class="py-3 px-4 text-emerald-400 font-mono text-xs">${u.phone_e164}</td>
                        <td class="py-3 px-4 text-xs text-slate-300">${(u.state || '--')} • ${(u.gender || '--')}</td>
                        <td class="py-3 px-4">
                            ${u.is_premium
                                ? '<span class="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50">★ PREMIUM</span>'
                                : '<span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300">Grátis</span>'}
                        </td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-0.5 rounded text-xs font-semibold ${u.reciprocity_score >= 1.0 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'}">
                                ${u.reciprocity_score.toFixed(2)}
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
                `).join('');
            } catch(e) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-rose-400">Erro ao buscar dados.</td></tr>';
            }
        }

        async function togglePremium(id) {
            await fetch(`/admin/users/${id}/toggle-premium`, { method: 'POST' });
            loadUsers();
            loadMetrics();
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
        loadMetrics();
        loadUsers();
        setInterval(loadMetrics, 10000);
    </script>
</body>
</html>
    """
