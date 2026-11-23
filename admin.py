import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from db_migrations import ensure_push_tables
from models import User, ContactExchange, Report, AuditLog, DeviceToken, PushCampaign
from schemas import PushSendRequest
from exchange_service import (
    brasilia_today_str,
    pause_expired_free_users,
    is_midnight_auto_pause_enabled,
    set_midnight_auto_pause_enabled,
    get_ads_settings,
    update_ads_settings,
)
from push_service import ensure_firebase_initialized, get_audience_counts, send_push_campaign

router = APIRouter(prefix="/admin", tags=["Administração"])

ADMIN_SESSION_COOKIE = "statuszap_admin_session"
ADMIN_SESSION_TTL_SECONDS = max(300, int(os.getenv("ADMIN_SESSION_TTL_SECONDS", str(8 * 3600))))
_LOGIN_RATE_WINDOW_SECONDS = 300
_LOGIN_MAX_ATTEMPTS = 10

_revoked_jtis: Dict[str, int] = {}
_failed_login_attempts: Dict[str, List[float]] = {}

_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class AdminLoginRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


class AutoPauseToggleRequest(BaseModel):
    enabled: Optional[bool] = None


class BulkPauseActionRequest(BaseModel):
    scope: str = Field(default="all")


class PremiumUpdateRequest(BaseModel):
    duration: str = Field(default="lifetime")  # 1m, 2m, 6m, 12m, lifetime, custom, remove
    expires_at: Optional[str] = Field(default=None)  # YYYY-MM-DD para data personalizada


class AdsSettingsUpdateRequest(BaseModel):
    ads_enabled: bool = True
    ads_banner_enabled: bool = True
    ads_interstitial_enabled: bool = True
    ads_interstitial_interval: int = Field(default=4, ge=1, le=50)


def _get_configured_admin_secret() -> str:
    expected = os.getenv("ADMIN_PUSH_SECRET", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Variável ADMIN_PUSH_SECRET não configurada no Railway. Defina uma senha de administrador nas variáveis do servidor."
        )
    return expected


def _derive_hmac_key(purpose: str, admin_secret: str) -> bytes:
    return hashlib.sha256(f"statuszap-admin:{purpose}:{admin_secret}".encode("utf-8")).digest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _purge_expired_revocations(now_ts: int) -> None:
    expired = [jti for jti, exp in _revoked_jtis.items() if exp <= now_ts]
    for jti in expired:
        _revoked_jtis.pop(jti, None)


def _compute_csrf_token(admin_secret: str, jti: str, exp_ts: int) -> str:
    digest = hmac.new(
        _derive_hmac_key("csrf", admin_secret),
        f"{jti}:{exp_ts}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _create_session_token(admin_secret: str) -> Tuple[str, str, int]:
    now_ts = int(time.time())
    exp_ts = now_ts + ADMIN_SESSION_TTL_SECONDS
    jti = secrets.token_urlsafe(18)
    payload = {
        "sub": "statuszap_admin",
        "jti": jti,
        "iat": now_ts,
        "exp": exp_ts,
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac.new(
        _derive_hmac_key("session", admin_secret),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    token = f"{payload_b64}.{_b64url_encode(sig)}"
    csrf_token = _compute_csrf_token(admin_secret, jti, exp_ts)
    return token, csrf_token, exp_ts


def _verify_session_token(token: str, admin_secret: str) -> Optional[Dict]:
    if not token or "." not in token:
        return None
    parts = token.split(".")
    if len(parts) != 2:
        return None
    payload_b64, sig_b64 = parts
    try:
        expected_sig = hmac.new(
            _derive_hmac_key("session", admin_secret),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None

    if not isinstance(payload, dict) or payload.get("sub") != "statuszap_admin":
        return None
    jti = payload.get("jti")
    exp = payload.get("exp")
    iat = payload.get("iat")
    if not isinstance(jti, str) or not jti or not isinstance(exp, int) or not isinstance(iat, int):
        return None

    now_ts = int(time.time())
    _purge_expired_revocations(now_ts)
    if jti in _revoked_jtis:
        return None
    if now_ts >= exp or iat > now_ts + 60:
        return None
    return payload


def _should_use_secure_cookie(request: Request) -> bool:
    env_override = os.getenv("ADMIN_COOKIE_SECURE", "").strip().lower()
    if env_override in {"false", "0", "no"}:
        return False
    if env_override in {"true", "1", "yes"}:
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    if forwarded_proto == "https" or request.url.scheme == "https":
        return True
    host = (request.headers.get("host", "") or request.url.hostname or "").split(":")[0].lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    return True


def _verify_same_origin(request: Request) -> None:
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return
    expected_host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip().lower()
    origin_host = urlparse(origin).netloc.strip().lower()
    if not expected_host or not origin_host or not hmac.compare_digest(origin_host, expected_host):
        raise HTTPException(
            status_code=403,
            detail="Origem não autorizada para acesso administrativo."
        )


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


def _get_valid_session_optional(request: Request) -> Optional[Tuple[Dict, str]]:
    try:
        admin_secret = _get_configured_admin_secret()
    except HTTPException:
        return None
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    session = _verify_session_token(token, admin_secret)
    if not session:
        return None
    return session, admin_secret


async def require_admin_read(request: Request) -> Dict:
    _verify_same_origin(request)
    admin_secret = _get_configured_admin_secret()
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    session = _verify_session_token(token, admin_secret)
    if not session:
        raise HTTPException(
            status_code=401,
            detail="Sessão administrativa ausente ou expirada. Faça login em /admin/login."
        )
    return session


async def require_admin_write(
    request: Request,
    x_csrf_token: str = Header(default="", alias="X-CSRF-Token"),
) -> Dict:
    _verify_same_origin(request)
    admin_secret = _get_configured_admin_secret()
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    session = _verify_session_token(token, admin_secret)
    if not session:
        raise HTTPException(
            status_code=401,
            detail="Sessão administrativa ausente ou expirada. Faça login novamente."
        )
    expected_csrf = _compute_csrf_token(admin_secret, session["jti"], int(session["exp"]))
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token.strip(), expected_csrf):
        raise HTTPException(
            status_code=403,
            detail="Token CSRF inválido ou ausente. Recarregue o painel administrativo."
        )
    return session


def _render_login_html(secret_configured: bool = True) -> str:
    missing_banner = ""
    if not secret_configured:
        missing_banner = (
            '<div class="mb-4 rounded-xl border border-amber-500/40 bg-amber-950/60 p-3.5 text-xs text-amber-200">'
            '<strong>Atenção:</strong> A variável <code>ADMIN_PUSH_SECRET</code> ainda não está configurada no Railway. '
            'Defina-a nas variáveis de ambiente do servidor antes de entrar.'
            '</div>'
        )
    html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Administrativo — StatusZap</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>body { font-family: 'Inter', sans-serif; }</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-7 shadow-2xl space-y-6">
        <div class="flex items-center gap-3">
            <div class="w-11 h-11 rounded-xl bg-emerald-500 flex items-center justify-center font-bold text-slate-950 text-xl shadow-lg shadow-emerald-500/20">
                SZ
            </div>
            <div>
                <h1 class="text-lg font-bold text-white">Painel Administrativo — StatusZap</h1>
                <p class="text-xs text-emerald-400">Acesso restrito com sessão segura e proteção CSRF</p>
            </div>
        </div>

        __MISSING_BANNER__

        <form id="adminLoginForm" onsubmit="submitAdminLogin(event)" class="space-y-4">
            <div>
                <label for="adminPassword" class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                    Senha Administrativa
                </label>
                <input id="adminPassword" type="password" required autocomplete="current-password"
                       placeholder="Digite a senha configurada no servidor"
                       class="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div id="loginErrorBox" class="hidden rounded-xl border border-rose-500/40 bg-rose-950/60 px-3.5 py-2.5 text-xs text-rose-200"></div>

            <button id="loginSubmitBtn" type="submit"
                    class="w-full py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm shadow-lg shadow-emerald-500/20 transition">
                Entrar no Painel
            </button>
        </form>

        <p class="text-[11px] text-slate-500 text-center">
            Autenticação validada com cookie HttpOnly, Secure e SameSite.
        </p>
    </div>

    <script>
        async function submitAdminLogin(event) {
            event.preventDefault();
            const pwdInput = document.getElementById('adminPassword');
            const errBox = document.getElementById('loginErrorBox');
            const btn = document.getElementById('loginSubmitBtn');
            const password = (pwdInput.value || '').trim();

            errBox.classList.add('hidden');
            if (!password) {
                errBox.textContent = 'Informe a senha administrativa.';
                errBox.classList.remove('hidden');
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Verificando...';

            try {
                const res = await fetch('/admin/login', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (!res.ok) {
                    errBox.textContent = data.detail || 'Senha inválida.';
                    errBox.classList.remove('hidden');
                    return;
                }
                window.location.href = data.redirect || '/admin/dashboard';
            } catch (e) {
                errBox.textContent = 'Erro de conexão com o servidor.';
                errBox.classList.remove('hidden');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Entrar no Painel';
            }
        }
    </script>
</body>
</html>"""
    return html.replace("__MISSING_BANNER__", missing_banner)


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if _get_valid_session_optional(request) is not None:
        return RedirectResponse(url="/admin/dashboard", status_code=303, headers=_NO_CACHE_HEADERS)
    secret_configured = bool(os.getenv("ADMIN_PUSH_SECRET", "").strip())
    return HTMLResponse(content=_render_login_html(secret_configured), headers=_NO_CACHE_HEADERS)


@router.post("/login")
async def admin_login_submit(
    payload: AdminLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    _verify_same_origin(request)
    admin_secret = _get_configured_admin_secret()
    client_ip = _get_client_ip(request)
    now_monotonic = time.time()

    attempts = [
        ts for ts in _failed_login_attempts.get(client_ip, [])
        if now_monotonic - ts < _LOGIN_RATE_WINDOW_SECONDS
    ]
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        _failed_login_attempts[client_ip] = attempts
        raise HTTPException(
            status_code=429,
            detail="Muitas tentativas de login. Aguarde alguns minutos antes de tentar novamente."
        )

    if not hmac.compare_digest(payload.password.strip(), admin_secret):
        attempts.append(now_monotonic)
        _failed_login_attempts[client_ip] = attempts
        raise HTTPException(
            status_code=401,
            detail="Senha administrativa incorreta."
        )

    _failed_login_attempts.pop(client_ip, None)
    token, _csrf_token, _exp_ts = _create_session_token(admin_secret)

    try:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_LOGIN_SUCCESS",
                ip_address=client_ip[:50],
                timestamp=datetime.datetime.utcnow(),
                details="Sessão administrativa autenticada com sucesso.",
            )
        )
        await db.commit()
    except Exception:
        await db.rollback()

    response = JSONResponse(
        content={"success": True, "redirect": "/admin/dashboard"},
        headers=_NO_CACHE_HEADERS,
    )
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=token,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        expires=ADMIN_SESSION_TTL_SECONDS,
        path="/admin",
        httponly=True,
        secure=_should_use_secure_cookie(request),
        samesite="lax",
    )
    return response


@router.post("/logout")
async def admin_logout(
    request: Request,
    session: Dict = Depends(require_admin_write),
    db: AsyncSession = Depends(get_db),
):
    _revoked_jtis[session["jti"]] = int(session["exp"])
    client_ip = _get_client_ip(request)
    try:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_LOGOUT",
                ip_address=client_ip[:50],
                timestamp=datetime.datetime.utcnow(),
                details="Administrador encerrou a sessão do painel.",
            )
        )
        await db.commit()
    except Exception:
        await db.rollback()

    response = JSONResponse(
        content={"success": True, "redirect": "/admin/login"},
        headers=_NO_CACHE_HEADERS,
    )
    response.delete_cookie(
        key=ADMIN_SESSION_COOKIE,
        path="/admin",
        httponly=True,
        secure=_should_use_secure_cookie(request),
        samesite="lax",
    )
    return response


@router.get("/metrics", dependencies=[Depends(require_admin_read)])
async def get_admin_metrics(db: AsyncSession = Depends(get_db)):
    auto_pause_enabled = await is_midnight_auto_pause_enabled(db)
    ads_settings = await get_ads_settings(db)
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
        "avg_reciprocity": round(float(avg_reciprocity), 2),
        "auto_midnight_pause_enabled": auto_pause_enabled,
        "ads_settings": ads_settings,
    }


@router.get("/settings/auto-pause", dependencies=[Depends(require_admin_read)])
async def get_auto_pause_setting(db: AsyncSession = Depends(get_db)):
    enabled = await is_midnight_auto_pause_enabled(db)
    return {"auto_midnight_pause_enabled": enabled}


@router.post("/settings/auto-pause/toggle", dependencies=[Depends(require_admin_write)])
async def toggle_auto_pause_setting(
    payload: Optional[AutoPauseToggleRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    current = await is_midnight_auto_pause_enabled(db)
    target = (not current) if (payload is None or payload.enabled is None) else bool(payload.enabled)
    await set_midnight_auto_pause_enabled(db, target)
    if target:
        await pause_expired_free_users(db)
    return {
        "success": True,
        "auto_midnight_pause_enabled": target,
        "message": (
            "Pausamento automático à meia-noite (00:00) ATIVADO. O app continua operando normalmente para o plano Grátis."
            if target
            else "Pausamento automático à meia-noite DESATIVADO. Os contatos não param de ser distribuídos às 00:00."
        ),
    }


@router.get("/settings/ads", dependencies=[Depends(require_admin_read)])
async def get_admin_ads_settings(db: AsyncSession = Depends(get_db)):
    return await get_ads_settings(db)


@router.post("/settings/ads", dependencies=[Depends(require_admin_write)])
async def save_admin_ads_settings(
    payload: AdsSettingsUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    updated = await update_ads_settings(
        db=db,
        ads_enabled=payload.ads_enabled,
        ads_banner_enabled=payload.ads_banner_enabled,
        ads_interstitial_enabled=payload.ads_interstitial_enabled,
        ads_interstitial_interval=payload.ads_interstitial_interval,
    )
    return {
        "success": True,
        "ads_settings": updated,
        "message": (
            f"Configuração de anúncios salva! Tela cheia a cada {updated['ads_interstitial_interval']} interações."
            if updated["ads_enabled"] and updated["ads_interstitial_enabled"]
            else "Configuração de anúncios AdMob atualizada com sucesso."
        ),
    }

@router.get("/users", dependencies=[Depends(require_admin_read)])
async def list_admin_users(
    response: Response,
    search: str = Query(default=""),
    status: str = Query(default="all"),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    await pause_expired_free_users(db)

    filters = []
    clean_search = search.strip()
    if clean_search:
        filters.append(User.name.ilike(f"%{clean_search}%") | User.phone_e164.ilike(f"%{clean_search}%"))

    normalized_status = (status or "all").strip().lower()
    if normalized_status == "active":
        filters.extend([User.is_active == True, User.is_paused == False])
    elif normalized_status == "paused":
        filters.extend([User.is_active == True, User.is_paused == True])
    elif normalized_status == "premium":
        filters.append(User.is_premium == True)
    elif normalized_status == "free":
        filters.append(User.is_premium == False)
    elif normalized_status == "blocked":
        filters.append(User.is_active == False)

    count_query = select(func.count(User.id))
    query = select(User)
    if filters:
        count_query = count_query.where(*filters)
        query = query.where(*filters)

    total_count = int((await db.execute(count_query)).scalar() or 0)
    query = query.order_by(desc(User.is_premium), desc(User.created_at), desc(User.id)).offset(offset).limit(limit)
    res = await db.execute(query)
    users = res.scalars().all()

    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-Limit"] = str(limit)
    response.headers["X-Offset"] = str(offset)

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

    now_utc = datetime.datetime.utcnow()

    def _calc_days_left(exp: Optional[datetime.datetime]) -> Optional[int]:
        if exp is None:
            return None
        diff_seconds = (exp - now_utc).total_seconds()
        if diff_seconds <= 0:
            return 0
        return int((diff_seconds + 86399) // 86400)

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
            "premium_expires_at": u.premium_expires_at.isoformat() if (u.is_premium and u.premium_expires_at) else None,
            "premium_days_left": _calc_days_left(u.premium_expires_at) if u.is_premium else None,
            "has_fcm_token": token_counts.get(u.id, 0) > 0,
            "fcm_token_count": token_counts.get(u.id, 0),
            "total_received": u.total_contacts_received,
            "total_shared": u.total_contacts_shared,
            "reciprocity_score": float(u.reciprocity_score if u.reciprocity_score is not None else 1.0),
            "created_at": u.created_at.isoformat() if u.created_at else ""
        }
        for u in users
    ]


@router.post("/users/bulk-pause", dependencies=[Depends(require_admin_write)])
async def bulk_pause_users(
    payload: Optional[BulkPauseActionRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    scope = ((payload.scope if payload else "all") or "all").strip().lower()
    if scope not in ("all", "free", "premium"):
        raise HTTPException(status_code=400, detail="Escopo inválido. Use 'all', 'free' ou 'premium'.")

    conditions = [User.is_active == True, User.is_paused == False]
    if scope == "free":
        conditions.append(User.is_premium == False)
    elif scope == "premium":
        conditions.append(User.is_premium == True)

    count_res = await db.execute(select(func.count(User.id)).where(*conditions))
    affected_count = int(count_res.scalar() or 0)

    if affected_count > 0:
        await db.execute(
            update(User)
            .where(*conditions)
            .values(is_paused=True, updated_at=datetime.datetime.utcnow())
        )
        db.add(AuditLog(
            user_id=None,
            action="ADMIN_BULK_PAUSE",
            timestamp=datetime.datetime.utcnow(),
            details=f"Administrador pausou {affected_count} usuários em massa (escopo={scope})."
        ))
        await db.commit()

    return {
        "success": True,
        "affected_count": affected_count,
        "scope": scope,
        "message": (
            f"{affected_count} usuário(s) pausado(s) com sucesso."
            if affected_count > 0
            else "Nenhum usuário ativo disponível para pausar."
        )
    }


@router.post("/users/bulk-activate", dependencies=[Depends(require_admin_write)])
async def bulk_activate_users(
    payload: Optional[BulkPauseActionRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    scope = ((payload.scope if payload else "all") or "all").strip().lower()
    if scope not in ("all", "free", "premium"):
        raise HTTPException(status_code=400, detail="Escopo inválido. Use 'all', 'free' ou 'premium'.")

    conditions = [User.is_active == True, User.is_paused == True]
    if scope == "free":
        conditions.append(User.is_premium == False)
    elif scope == "premium":
        conditions.append(User.is_premium == True)

    count_res = await db.execute(select(func.count(User.id)).where(*conditions))
    affected_count = int(count_res.scalar() or 0)
    today_brt = brasilia_today_str()

    if affected_count > 0:
        await db.execute(
            update(User)
            .where(*conditions)
            .values(
                is_paused=False,
                last_active_date=today_brt,
                updated_at=datetime.datetime.utcnow(),
            )
        )
        db.add(AuditLog(
            user_id=None,
            action="ADMIN_BULK_ACTIVATE",
            timestamp=datetime.datetime.utcnow(),
            details=f"Administrador ativou {affected_count} usuários pausados em massa (escopo={scope})."
        ))
        await db.commit()

    return {
        "success": True,
        "affected_count": affected_count,
        "scope": scope,
        "message": (
            f"{affected_count} usuário(s) ativado(s) com sucesso!"
            if affected_count > 0
            else "Todos os usuários elegíveis já estão ativos."
        )
    }


@router.post("/users/{user_id}/premium", dependencies=[Depends(require_admin_write)])
async def set_user_premium_plan(
    user_id: int,
    payload: PremiumUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    now = datetime.datetime.utcnow()
    duration = (payload.duration or "lifetime").strip().lower()
    duration_days_map = {
        "1m": (30, "1 mês (30 dias)"),
        "2m": (60, "2 meses (60 dias)"),
        "6m": (180, "6 meses (180 dias)"),
        "12m": (365, "1 ano (365 dias)"),
    }

    if duration == "remove":
        user.is_premium = False
        user.premium_expires_at = None
        user.last_active_date = brasilia_today_str()
        user.updated_at = now
        plan_label = "Grátis"
        action_name = "PREMIUM_REVOKED"
        details = f"Administrador removeu o plano Premium de {user.name}."
        msg = f"Plano Premium removido de {user.name} (voltou para Grátis)."
    elif duration == "lifetime":
        user.is_premium = True
        user.premium_expires_at = None
        user.is_paused = False
        user.last_active_date = brasilia_today_str()
        user.updated_at = now
        plan_label = "★ Vitalício"
        action_name = "PREMIUM_GRANTED"
        details = f"Administrador ativou Premium Vitalício para {user.name}."
        msg = f"{user.name} agora é ★ Premium Vitalício!"
    elif duration in duration_days_map:
        days, label = duration_days_map[duration]
        # Se já é Premium com validade futura, soma a partir de hoje (renovação limpa a partir de agora)
        expires_at = now + datetime.timedelta(days=days)
        user.is_premium = True
        user.premium_expires_at = expires_at
        user.is_paused = False
        user.last_active_date = brasilia_today_str()
        user.updated_at = now
        brt_exp = expires_at - datetime.timedelta(hours=3)
        exp_str = brt_exp.strftime("%d/%m/%Y")
        plan_label = f"Válido até {exp_str}"
        action_name = "PREMIUM_GRANTED"
        details = f"Administrador ativou Premium ({label}) para {user.name}, válido até {exp_str}."
        msg = f"{user.name} agora é ★ Premium por {label} (válido até {exp_str})!"
    elif duration == "custom":
        raw_date = (payload.expires_at or "").strip()
        if not raw_date:
            raise HTTPException(status_code=400, detail="Informe a data de validade (YYYY-MM-DD).")
        try:
            parsed_date = datetime.datetime.strptime(raw_date[:10], "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Data inválida. Use o formato AAAA-MM-DD.")
        # Fim do dia no horário de Brasília (23:59:59 BRT = +03:00 UTC)
        expires_at = parsed_date.replace(hour=23, minute=59, second=59) + datetime.timedelta(hours=3)
        if expires_at <= now:
            raise HTTPException(status_code=400, detail="A data de validade deve ser no futuro.")
        user.is_premium = True
        user.premium_expires_at = expires_at
        user.is_paused = False
        user.last_active_date = brasilia_today_str()
        user.updated_at = now
        exp_str = parsed_date.strftime("%d/%m/%Y")
        plan_label = f"Válido até {exp_str}"
        action_name = "PREMIUM_GRANTED"
        details = f"Administrador ativou Premium personalizado para {user.name}, válido até {exp_str}."
        msg = f"{user.name} agora é ★ Premium válido até {exp_str}!"
    else:
        raise HTTPException(status_code=400, detail="Duração inválida. Use 1m, 2m, 6m, 12m, lifetime, custom ou remove.")

    db.add(AuditLog(
        user_id=user.id,
        action=action_name,
        timestamp=now,
        details=details,
    ))
    await db.commit()
    return {
        "success": True,
        "is_premium": bool(user.is_premium),
        "premium_expires_at": user.premium_expires_at.isoformat() if user.premium_expires_at else None,
        "plan_label": plan_label,
        "message": msg,
    }


@router.post("/users/{user_id}/toggle-premium", dependencies=[Depends(require_admin_write)])
async def toggle_user_premium(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_premium = not bool(user.is_premium)
    if user.is_premium:
        user.is_paused = False
        user.premium_expires_at = None
    else:
        user.premium_expires_at = None
    audit = AuditLog(
        user_id=user.id,
        action="PREMIUM_GRANTED" if user.is_premium else "PREMIUM_REVOKED",
        timestamp=datetime.datetime.utcnow(),
        details=f"Administrador alterou o plano de {user.name} para {'Premium Vitalício' if user.is_premium else 'Grátis'}."
    )
    db.add(audit)
    await db.commit()
    return {
        "is_premium": user.is_premium,
        "premium_expires_at": None,
        "message": f"Usuário agora é {'★ Premium Vitalício' if user.is_premium else 'Grátis'}!"
    }

@router.post("/users/{user_id}/toggle-pause", dependencies=[Depends(require_admin_write)])
async def toggle_user_pause(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_paused = not user.is_paused
    if not user.is_paused:
        user.last_active_date = brasilia_today_str()
    await db.commit()
    return {"message": f"Usuário {'pausado' if user.is_paused else 'reativado'} com sucesso."}

@router.post("/users/{user_id}/toggle-active", dependencies=[Depends(require_admin_write)])
async def toggle_user_active(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    user.is_active = not user.is_active
    await db.commit()
    return {"message": f"Status do usuário alterado para {'ativo' if user.is_active else 'bloqueado'}."}

# --- Notificações Push (Protegido por Sessão Admin + CSRF) ---

@router.get("/push/summary", dependencies=[Depends(require_admin_read)])
async def get_push_summary(db: AsyncSession = Depends(get_db)):
    await ensure_push_tables()
    counts = await get_audience_counts(db)
    firebase_ok, firebase_err = ensure_firebase_initialized()
    return {
        "audience_counts": counts,
        "firebase_configured": firebase_ok,
        "firebase_error": firebase_err or ""
    }

@router.get("/push/history", dependencies=[Depends(require_admin_read)])
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

@router.post("/push/test", dependencies=[Depends(require_admin_write)])
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
            target_user_id=payload.target_user_id,
            action_label=payload.action_label,
            action_url=payload.action_url
        )
        return result
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@router.post("/push/send", dependencies=[Depends(require_admin_write)])
async def send_bulk_push(
    payload: PushSendRequest,
    db: AsyncSession = Depends(get_db)
):
    await ensure_push_tables()
    audience = payload.audience if payload.audience in {"all", "free", "premium", "paused"} else "all"
    try:
        result = await send_push_campaign(
            db=db,
            title=payload.title,
            body=payload.body,
            audience=audience,
            target_user_id=None,
            action_label=payload.action_label,
            action_url=payload.action_url
        )
        return result
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

@router.get("/reports", dependencies=[Depends(require_admin_read)])
async def list_reports(
    status: Optional[str] = Query(default="all"),
    limit: int = Query(default=100, ge=1, le=200),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Report)
    norm_status = (status or "all").strip().lower()
    if norm_status in {"pending", "resolved", "dismissed"}:
        stmt = stmt.where(Report.status == norm_status)
    stmt = stmt.order_by(desc(Report.created_at)).limit(limit)

    res = await db.execute(stmt)
    reports = list(res.scalars().all())
    # Prioriza denúncias pendentes no topo mantendo mais recentes primeiro
    reports.sort(key=lambda r: (0 if r.status == "pending" else 1, -(r.created_at.timestamp() if r.created_at else 0)))

    user_ids = set()
    for r in reports:
        if r.reported_user_id:
            user_ids.add(r.reported_user_id)
        if r.reporter_user_id:
            user_ids.add(r.reporter_user_id)

    users_map: Dict[int, User] = {}
    if user_ids:
        u_res = await db.execute(select(User).where(User.id.in_(list(user_ids))))
        for u in u_res.scalars().all():
            users_map[u.id] = u

    result = []
    for r in reports:
        reported = users_map.get(r.reported_user_id) if r.reported_user_id else None
        reporter = users_map.get(r.reporter_user_id) if r.reporter_user_id else None
        result.append({
            "id": r.id,
            "reporter_user_id": r.reporter_user_id,
            "reporter_name": reporter.name if reporter else "Visitante / Anônimo",
            "reporter_phone": reporter.phone_e164 if reporter else "",
            "reported_user_id": r.reported_user_id,
            "reported_name": reported.name if reported else f"Usuário #{r.reported_user_id}",
            "reported_phone": reported.phone_e164 if reported else "",
            "reported_is_active": bool(reported.is_active) if reported else False,
            "reported_is_paused": bool(reported.is_paused) if reported else False,
            "reported_is_premium": bool(reported.is_premium) if reported else False,
            "reason": r.reason,
            "details": r.details or "",
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else ""
        })
    return result

@router.post("/reports/{report_id}/resolve", dependencies=[Depends(require_admin_write)])
async def resolve_report(report_id: int, action: str = "resolve", db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Denúncia não encontrada.")

    norm_action = (action or "resolve").strip().lower()
    reported_user = await db.get(User, report.reported_user_id) if report.reported_user_id else None
    now = datetime.datetime.utcnow()

    if norm_action == "ban":
        report.status = "resolved"
        if reported_user:
            reported_user.is_active = False
        msg = "Usuário denunciado bloqueado e denúncia marcada como resolvida."
        audit_detail = f"Denúncia #{report.id}: usuário #{report.reported_user_id} bloqueado."
    elif norm_action == "pause":
        report.status = "resolved"
        if reported_user:
            reported_user.is_paused = True
        msg = "Distribuição do usuário denunciado pausada e denúncia resolvida."
        audit_detail = f"Denúncia #{report.id}: usuário #{report.reported_user_id} pausado."
    elif norm_action == "dismiss":
        report.status = "dismissed"
        msg = "Denúncia descartada sem punição ao usuário."
        audit_detail = f"Denúncia #{report.id} descartada."
    elif norm_action == "reopen":
        report.status = "pending"
        msg = "Denúncia reaberta como pendente."
        audit_detail = f"Denúncia #{report.id} reaberta."
    else:
        report.status = "resolved"
        msg = "Denúncia marcada como resolvida."
        audit_detail = f"Denúncia #{report.id} marcada como resolvida."

    db.add(AuditLog(
        user_id=report.reported_user_id,
        action=f"ADMIN_REPORT_{norm_action.upper()}",
        timestamp=now,
        details=audit_detail
    ))
    await db.commit()
    return {"message": msg, "status": report.status}

@router.delete("/reports/{report_id}", dependencies=[Depends(require_admin_write)])
async def delete_report(report_id: int, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Denúncia não encontrada.")
    await db.delete(report)
    await db.commit()
    return {"message": "Registro de denúncia excluído."}

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    auth_info = _get_valid_session_optional(request)
    if auth_info is None:
        return RedirectResponse(url="/admin/login", status_code=303, headers=_NO_CACHE_HEADERS)

    session, admin_secret = auth_info
    csrf_token = _compute_csrf_token(admin_secret, session["jti"], int(session["exp"]))

    # Painel administrativo visual completo e responsivo integrado na FastAPI
    html = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="__CSRF_TOKEN__">
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
        <div class="flex flex-wrap items-center gap-3">
            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                Sessão Protegida
            </span>
            <a href="/docs" target="_blank" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                API Docs (Swagger)
            </a>
            <button onclick="logoutAdmin()" class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600/90 hover:bg-rose-500 text-white border border-rose-500/50 transition">
                Sair
            </button>
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
            <button type="button" onclick="scrollToReportsSection()" class="text-left bg-slate-800/80 hover:bg-slate-800 border border-amber-500/40 hover:border-amber-400 rounded-2xl p-5 shadow-sm transition cursor-pointer">
                <p class="text-xs font-medium text-amber-300 uppercase tracking-wider">Denúncias Pendentes</p>
                <p id="pendingReports" class="text-3xl font-bold text-amber-400 mt-2">--</p>
                <p class="text-xs text-slate-400 mt-1">Clique para gerenciar denúncias ↓</p>
            </button>
        </div>

        <!-- Controle Global: Pausamento Automático à Meia-Noite (00:00) -->
        <section class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div class="space-y-1">
                <div class="flex flex-wrap items-center gap-2.5">
                    <h2 class="text-base font-semibold text-white">Pausamento Automático da Distribuição (00:00 Brasília)</h2>
                    <span id="autoPauseStatusBadge" class="text-xs font-bold px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600">
                        Carregando...
                    </span>
                </div>
                <p id="autoPauseDescription" class="text-sm text-slate-400">
                    Carregando configuração atual do pausamento automático para usuários do plano Grátis...
                </p>
            </div>
            <div class="flex items-center gap-3 shrink-0">
                <button id="toggleAutoPauseBtn" onclick="toggleGlobalAutoPause()" disabled
                        class="px-5 py-2.5 rounded-xl font-semibold text-sm bg-slate-700 text-slate-300 transition whitespace-nowrap">
                    Carregando...
                </button>
            </div>
        </section>

        <!-- Controle Global: Anúncios (Google AdMob) -->
        <section class="bg-slate-800/80 border border-sky-700/40 rounded-2xl p-6 shadow-sm space-y-5">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-700/70 pb-4">
                <div>
                    <div class="flex flex-wrap items-center gap-2.5">
                        <h2 class="text-base font-semibold text-white">Anúncios do Aplicativo (Google AdMob)</h2>
                        <span id="adsStatusBadge" class="text-xs font-bold px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600">
                            Carregando...
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-1">
                        Controle o banner inferior e a frequência de anúncios em tela cheia (intersticial). Usuários <span class="text-amber-300 font-semibold">★ Premium</span> nunca veem anúncios.
                    </p>
                </div>
                <button id="saveAdsBtn" onclick="saveAdsSettings()" disabled
                        class="px-5 py-2.5 rounded-xl font-semibold text-sm bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-lg shadow-sky-500/15 transition whitespace-nowrap">
                    Salvar Configuração de Anúncios
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <label class="flex items-center justify-between gap-3 rounded-xl bg-slate-900/80 border border-slate-700/80 px-4 py-3 cursor-pointer">
                    <div>
                        <p class="text-sm font-semibold text-white">Anúncios Ativos</p>
                        <p class="text-[11px] text-slate-400">Chave geral do AdMob</p>
                    </div>
                    <input id="adsEnabledToggle" type="checkbox" checked class="w-5 h-5 accent-emerald-500 rounded">
                </label>

                <label class="flex items-center justify-between gap-3 rounded-xl bg-slate-900/80 border border-slate-700/80 px-4 py-3 cursor-pointer">
                    <div>
                        <p class="text-sm font-semibold text-white">Banner Inferior</p>
                        <p class="text-[11px] text-slate-400">Fixo na parte de baixo</p>
                    </div>
                    <input id="adsBannerToggle" type="checkbox" checked class="w-5 h-5 accent-emerald-500 rounded">
                </label>

                <label class="flex items-center justify-between gap-3 rounded-xl bg-slate-900/80 border border-slate-700/80 px-4 py-3 cursor-pointer">
                    <div>
                        <p class="text-sm font-semibold text-white">Tela Cheia</p>
                        <p class="text-[11px] text-slate-400">Intersticial por interações</p>
                    </div>
                    <input id="adsInterstitialToggle" type="checkbox" checked class="w-5 h-5 accent-emerald-500 rounded">
                </label>

                <div class="rounded-xl bg-slate-900/80 border border-slate-700/80 px-4 py-3 space-y-2">
                    <div class="flex items-center justify-between gap-2">
                        <label for="adsIntervalInput" class="text-xs font-semibold text-slate-200">
                            Interações p/ Tela Cheia
                        </label>
                        <input id="adsIntervalInput" type="number" min="1" max="50" value="4"
                               class="w-16 bg-slate-950 border border-slate-600 rounded-lg px-2 py-1 text-center text-sm font-bold text-sky-300 focus:outline-none focus:ring-2 focus:ring-sky-500">
                    </div>
                    <div class="flex flex-wrap gap-1.5">
                        <button type="button" onclick="setAdsIntervalPreset(2)" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">2x</button>
                        <button type="button" onclick="setAdsIntervalPreset(3)" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">3x</button>
                        <button type="button" onclick="setAdsIntervalPreset(4)" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">4x</button>
                        <button type="button" onclick="setAdsIntervalPreset(6)" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">6x</button>
                        <button type="button" onclick="setAdsIntervalPreset(10)" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">10x</button>
                    </div>
                </div>
            </div>
            <div id="adsSaveFeedback" class="hidden rounded-xl px-4 py-2.5 text-xs font-medium"></div>
        </section>

        <!-- Seção de Notificações Push (Firebase FCM) -->
        <section class="bg-slate-800/80 border border-emerald-700/40 rounded-2xl p-6 shadow-sm space-y-6">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-700/70 pb-4">
                <div>
                    <div class="flex items-center gap-2.5">
                        <h2 class="text-lg font-semibold text-white">Notificações Push</h2>
                        <span id="fcmStatusBadge" class="text-xs px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600">
                            Verificando status FCM...
                        </span>
                    </div>
                    <p class="text-sm text-slate-400 mt-0.5">Envie avisos pelo Firebase Cloud Messaging (FCM) com prévia, teste individual e histórico.</p>
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

                    <!-- Botão de ação opcional na tela exclusiva de notificação -->
                    <div class="bg-slate-900/60 border border-slate-700/80 rounded-xl p-3.5 space-y-2.5">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <span class="text-xs font-semibold uppercase tracking-wider text-emerald-400">Botão na Tela de Comunicado (Opcional)</span>
                            <div class="flex items-center gap-1.5">
                                <button type="button" onclick="applyPushPlansPreset()" class="text-[11px] px-2 py-0.5 rounded bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/40 transition">★ Planos Premium</button>
                                <button type="button" onclick="clearPushActionPreset()" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition">Limpar</button>
                            </div>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                            <input id="pushActionLabelInput" type="text" maxlength="60" oninput="updatePushPreview()"
                                   placeholder="Texto do botão (ex.: Ver Planos)"
                                   class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500">
                            <input id="pushActionUrlInput" type="text" maxlength="500" oninput="updatePushPreview()"
                                   placeholder="Link https://... ou digite plans"
                                   class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500">
                        </div>
                        <p class="text-[11px] text-slate-400">Se preenchido, o botão aparecerá na tela exclusiva aberta quando o usuário tocar na notificação.</p>
                    </div>

                    <!-- Destinatários -->
                    <div>
                        <label class="text-xs font-semibold uppercase tracking-wider text-slate-300 block mb-2">Destinatários</label>
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
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
                            <label class="cursor-pointer bg-slate-900/80 border border-orange-500/40 rounded-xl p-3 flex items-center justify-between hover:border-orange-400 transition">
                                <div class="flex items-center gap-2">
                                    <input type="radio" name="pushAudience" value="paused" class="accent-orange-400">
                                    <span class="text-sm font-medium text-orange-300">Somente Pausados</span>
                                </div>
                                <span id="countPaused" class="text-xs font-bold text-orange-300">--</span>
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
                                    <div id="previewActionWrap" class="hidden mt-2 pt-2 border-t border-slate-800">
                                        <span id="previewActionPill" class="inline-flex items-center px-2.5 py-1 rounded-lg text-[11px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">Abrir Link</span>
                                    </div>
                                </div>
                            </div>
                            <p class="text-[11px] text-slate-500">Ao tocar na notificação, o app abre a <strong>Tela Exclusiva de Comunicado</strong> com título, mensagem completa e botão opcional.</p>
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
                                <td colspan="7" class="text-center py-5 text-slate-500">Carregando histórico de envios...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Seção de Moderação de Denúncias -->
        <section id="reportsSection" class="bg-slate-800/80 border border-amber-600/40 rounded-2xl p-6 shadow-sm space-y-4">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <div class="flex flex-wrap items-center gap-2.5">
                        <h2 class="text-lg font-semibold text-white">Moderação de Denúncias</h2>
                        <span id="reportsSectionBadge" class="text-xs font-bold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            Carregando...
                        </span>
                    </div>
                    <p class="text-sm text-slate-400 mt-0.5">Analise denúncias enviadas pelos participantes e bloqueie, pause, resolva ou descarte cada caso.</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <select id="reportsStatusFilter" onchange="loadReports()" class="bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs font-semibold text-white focus:outline-none focus:ring-2 focus:ring-amber-500">
                        <option value="all">Todas as denúncias</option>
                        <option value="pending" selected>Somente pendentes</option>
                        <option value="resolved">Resolvidas</option>
                        <option value="dismissed">Descartadas</option>
                    </select>
                    <button onclick="loadReports()" class="px-3.5 py-2 rounded-xl bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-semibold transition">
                        Atualizar
                    </button>
                </div>
            </div>

            <div id="reportsFeedback" class="hidden rounded-xl px-4 py-2.5 text-xs font-medium"></div>

            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="bg-slate-900/60 uppercase text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="py-3 px-3">Data / Status</th>
                            <th class="py-3 px-3">Usuário Denunciado</th>
                            <th class="py-3 px-3">Motivo &amp; Detalhes</th>
                            <th class="py-3 px-3">Denunciado Por</th>
                            <th class="py-3 px-3 text-right">Ações</th>
                        </tr>
                    </thead>
                    <tbody id="reportsTableBody" class="divide-y divide-slate-700/60">
                        <tr>
                            <td colspan="5" class="text-center py-6 text-slate-500">Carregando denúncias...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Seção de Gerenciamento de Usuários -->
        <div class="bg-slate-800/80 border border-slate-700/80 rounded-2xl p-6 shadow-sm">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
                <div>
                    <h2 class="text-lg font-semibold text-white">Participantes da Rede</h2>
                    <p class="text-sm text-slate-400">Gerencie usuários, planos Premium/Grátis, tokens push e status de compartilhamento</p>
                </div>
                <div class="flex flex-wrap items-center gap-2.5">
                    <button id="btnBulkPauseAll" onclick="bulkPauseAllUsers()"
                            class="px-3.5 py-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-semibold text-sm rounded-xl transition">
                        ⏸ Pausar Todos
                    </button>
                    <button id="btnBulkActivateAll" onclick="bulkActivateAllUsers()"
                            class="px-3.5 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-semibold text-sm rounded-xl transition">
                        ▶ Ativar Todos
                    </button>
                </div>
            </div>

            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
                <div class="flex flex-wrap items-center gap-2.5 flex-1">
                    <input id="searchInput" type="text" placeholder="Buscar por nome ou WhatsApp..."
                           onkeydown="if (event.key === 'Enter') searchUsersFromStart();"
                           class="bg-slate-900 border border-slate-700 rounded-xl px-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 w-full sm:w-72">
                    <select id="userStatusFilter" onchange="searchUsersFromStart()"
                            class="bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500">
                        <option value="all">Todos os Status</option>
                        <option value="active">Somente Ativos</option>
                        <option value="paused">Somente Pausados</option>
                        <option value="premium">★ Somente Premium</option>
                        <option value="free">Somente Grátis</option>
                        <option value="blocked">Bloqueados</option>
                    </select>
                    <button onclick="searchUsersFromStart()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm rounded-xl transition">
                        Buscar
                    </button>
                </div>
                <div class="flex items-center gap-2 text-xs text-slate-400">
                    <label for="usersPageSizeSelect">Por página:</label>
                    <select id="usersPageSizeSelect" onchange="changeUsersPageSize()"
                            class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:ring-2 focus:ring-emerald-500">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                        <option value="200">200</option>
                    </select>
                </div>
            </div>

            <div id="usersBulkFeedback" class="hidden mb-4 rounded-xl px-4 py-2.5 text-sm border"></div>

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

            <!-- Paginação -->
            <div class="mt-5 pt-4 border-t border-slate-700/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div id="usersPaginationInfo" class="text-xs text-slate-400">
                    Carregando paginação...
                </div>
                <div class="flex items-center gap-2 flex-wrap">
                    <button id="btnUsersFirst" onclick="goToUsersPage(1)" disabled
                            class="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
                        « Primeira
                    </button>
                    <button id="btnUsersPrev" onclick="goToUsersPage(currentUsersPage - 1)" disabled
                            class="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
                        ‹ Anterior
                    </button>
                    <span id="usersPageIndicator" class="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-700/80 text-xs font-semibold text-white">
                        Página 1 de 1
                    </span>
                    <button id="btnUsersNext" onclick="goToUsersPage(currentUsersPage + 1)" disabled
                            class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white disabled:bg-slate-900 disabled:border disabled:border-slate-700 disabled:text-slate-500 disabled:opacity-50 disabled:cursor-not-allowed transition">
                        Próxima ›
                    </button>
                    <button id="btnUsersLast" onclick="goToUsersPage(totalUsersPages)" disabled
                            class="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
                        Última »
                    </button>
                </div>
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

    <!-- Modal de Escolha de Validade do Plano Premium -->
    <div id="premiumPlanModal" class="hidden fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-amber-500/40 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-start justify-between gap-3">
                <div>
                    <h3 class="text-lg font-bold text-amber-300">★ Definir Plano Premium</h3>
                    <p id="premiumModalUserInfo" class="text-sm text-slate-300 mt-0.5">--</p>
                </div>
                <button onclick="closePremiumModal()" class="text-slate-400 hover:text-white text-lg leading-none px-2 py-1 rounded-lg hover:bg-slate-700">✕</button>
            </div>

            <div id="premiumModalCurrentStatus" class="text-xs px-3 py-2 rounded-xl bg-slate-900/90 border border-slate-700 text-slate-300">
                Status atual: --
            </div>

            <div class="space-y-2">
                <p class="text-xs font-semibold uppercase tracking-wider text-slate-400">Escolha o tempo de validade</p>
                <div class="grid grid-cols-2 gap-2.5">
                    <button onclick="applyPremiumDuration('1m')" class="premium-dur-btn px-3.5 py-3 rounded-xl bg-slate-900 hover:bg-amber-500/20 border border-slate-700 hover:border-amber-500/60 text-left transition">
                        <div class="text-sm font-bold text-white">1 Mês</div>
                        <div class="text-xs text-slate-400">30 dias de acesso</div>
                    </button>
                    <button onclick="applyPremiumDuration('2m')" class="premium-dur-btn px-3.5 py-3 rounded-xl bg-slate-900 hover:bg-amber-500/20 border border-slate-700 hover:border-amber-500/60 text-left transition">
                        <div class="text-sm font-bold text-white">2 Meses</div>
                        <div class="text-xs text-slate-400">60 dias de acesso</div>
                    </button>
                    <button onclick="applyPremiumDuration('6m')" class="premium-dur-btn px-3.5 py-3 rounded-xl bg-slate-900 hover:bg-amber-500/20 border border-slate-700 hover:border-amber-500/60 text-left transition">
                        <div class="text-sm font-bold text-white">6 Meses</div>
                        <div class="text-xs text-slate-400">180 dias de acesso</div>
                    </button>
                    <button onclick="applyPremiumDuration('lifetime')" class="premium-dur-btn px-3.5 py-3 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/50 text-left transition">
                        <div class="text-sm font-bold text-amber-300">★ Vitalício</div>
                        <div class="text-xs text-amber-200/80">Sem data de expiração</div>
                    </button>
                </div>
            </div>

            <div class="pt-2 border-t border-slate-700/70 space-y-2">
                <label for="premiumCustomDateInput" class="block text-xs font-semibold text-slate-400">Ou escolha uma data exata de validade:</label>
                <div class="flex gap-2">
                    <input id="premiumCustomDateInput" type="date"
                           class="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-amber-500">
                    <button onclick="applyPremiumDuration('custom')" class="premium-dur-btn px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold transition">
                        Salvar Data
                    </button>
                </div>
            </div>

            <div class="flex items-center justify-between gap-2 pt-2 border-t border-slate-700/70">
                <button id="btnModalRemovePremium" onclick="applyPremiumDuration('remove')"
                        class="hidden premium-dur-btn px-3.5 py-2 rounded-xl bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-500/40 text-xs font-semibold transition">
                    Remover Premium (Grátis)
                </button>
                <button onclick="closePremiumModal()" class="ml-auto px-4 py-2 rounded-xl bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-medium transition">
                    Fechar
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

        function getCsrfToken() {
            const meta = document.querySelector('meta[name="csrf-token"]');
            return meta ? (meta.getAttribute('content') || '') : '';
        }

        async function adminFetch(url, options = {}) {
            const method = (options.method || 'GET').toUpperCase();
            const headers = Object.assign({}, options.headers || {});
            if (method !== 'GET' && method !== 'HEAD') {
                headers['X-CSRF-Token'] = getCsrfToken();
            }
            const res = await fetch(url, Object.assign({}, options, {
                credentials: 'same-origin',
                headers
            }));
            if (res.status === 401) {
                window.location.href = '/admin/login';
                throw new Error('Sessão administrativa expirada');
            }
            return res;
        }

        async function logoutAdmin() {
            try {
                const res = await adminFetch('/admin/logout', { method: 'POST' });
                const data = await res.json();
                window.location.href = (data && data.redirect) ? data.redirect : '/admin/login';
            } catch (e) {
                window.location.href = '/admin/login';
            }
        }

        function applyPushPlansPreset() {
            document.getElementById('pushActionLabelInput').value = 'Ver Planos Premium';
            document.getElementById('pushActionUrlInput').value = 'plans';
            updatePushPreview();
        }

        function clearPushActionPreset() {
            document.getElementById('pushActionLabelInput').value = '';
            document.getElementById('pushActionUrlInput').value = '';
            updatePushPreview();
        }

        function updatePushPreview() {
            const title = document.getElementById('pushTitleInput').value;
            const body = document.getElementById('pushBodyInput').value;
            const actionLabel = (document.getElementById('pushActionLabelInput')?.value || '').trim();
            const actionUrl = (document.getElementById('pushActionUrlInput')?.value || '').trim();
            document.getElementById('titleCounter').textContent = `${title.length}/120`;
            document.getElementById('bodyCounter').textContent = `${body.length}/500`;
            document.getElementById('previewTitle').textContent = title.trim() || 'Título da notificação';
            document.getElementById('previewBody').textContent = body.trim() || 'A mensagem aparecerá aqui exatamente como será exibida antes de enviar.';
            const wrap = document.getElementById('previewActionWrap');
            const pill = document.getElementById('previewActionPill');
            if (wrap && pill) {
                if (actionUrl) {
                    const isPlans = ['plans', 'premium', 'planos'].includes(actionUrl.toLowerCase());
                    pill.textContent = actionLabel || (isPlans ? 'Ver Planos Premium' : 'Abrir Link');
                    wrap.classList.remove('hidden');
                } else {
                    wrap.classList.add('hidden');
                }
            }
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
            if (aud === 'paused') return 'Somente com número pausado';
            if (aud === 'test') return 'Teste individual';
            return 'Todos os usuários';
        }

        async function loadPushSummary() {
            const badge = document.getElementById('fcmStatusBadge');
            try {
                const res = await adminFetch('/admin/push/summary');
                const data = await res.json();
                if (!res.ok) {
                    badge.textContent = data.detail || 'Erro ao verificar FCM';
                    badge.className = 'text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40';
                    return;
                }
                const counts = data.audience_counts || {};
                document.getElementById('countAll').textContent = counts.all ?? 0;
                document.getElementById('countFree').textContent = counts.free ?? 0;
                document.getElementById('countPremium').textContent = counts.premium ?? 0;
                const countPausedEl = document.getElementById('countPaused');
                if (countPausedEl) countPausedEl.textContent = counts.paused ?? 0;

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
            const tbody = document.getElementById('pushHistoryBody');
            try {
                const res = await adminFetch('/admin/push/history');
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
                    const dt = r.created_at ? new Date(r.created_at + 'Z').toLocaleString('pt-BR') : '--';
                    const audTag = r.audience === 'premium'
                        ? '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300">Premium</span>'
                        : r.audience === 'free'
                        ? '<span class="px-2 py-0.5 rounded-full bg-slate-700 text-slate-200">Grátis</span>'
                        : r.audience === 'paused'
                        ? '<span class="px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-300">Pausados</span>'
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
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            const actionLabel = (document.getElementById('pushActionLabelInput')?.value || '').trim();
            const actionUrl = (document.getElementById('pushActionUrlInput')?.value || '').trim();
            const targetUserId = Number(document.getElementById('testUserSelect').value || 0);

            if (!title || !body) {
                showPushResult(false, 'Preencha o título e a mensagem da notificação antes de enviar o teste.');
                return;
            }
            if (!targetUserId) {
                showPushResult(false, 'Selecione o usuário/número do seu celular na lista de teste.');
                return;
            }

            try {
                const res = await adminFetch('/admin/push/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title,
                        body,
                        audience: 'test',
                        target_user_id: targetUserId,
                        action_label: actionLabel || null,
                        action_url: actionUrl || null
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
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            if (!title || !body) {
                showPushResult(false, 'Preencha o título e a mensagem antes de enviar.');
                return;
            }
            const aud = document.querySelector('input[name="pushAudience"]:checked').value;
            const countMap = {
                all: document.getElementById('countAll').textContent,
                free: document.getElementById('countFree').textContent,
                premium: document.getElementById('countPremium').textContent,
                paused: document.getElementById('countPaused').textContent
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
            const title = document.getElementById('pushTitleInput').value.trim();
            const body = document.getElementById('pushBodyInput').value.trim();
            const actionLabel = (document.getElementById('pushActionLabelInput')?.value || '').trim();
            const actionUrl = (document.getElementById('pushActionUrlInput')?.value || '').trim();
            const aud = document.querySelector('input[name="pushAudience"]:checked').value;
            const btn = document.getElementById('confirmSendBtn');
            btn.disabled = true;
            btn.textContent = 'Enviando...';

            try {
                const res = await adminFetch('/admin/push/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title,
                        body,
                        audience: aud,
                        action_label: actionLabel || null,
                        action_url: actionUrl || null
                    })
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

        let currentAutoPauseEnabled = true;

        function renderAutoPauseControl(enabled) {
            currentAutoPauseEnabled = Boolean(enabled);
            const badge = document.getElementById('autoPauseStatusBadge');
            const desc = document.getElementById('autoPauseDescription');
            const btn = document.getElementById('toggleAutoPauseBtn');
            if (!badge || !desc || !btn) return;

            btn.disabled = false;
            if (currentAutoPauseEnabled) {
                badge.textContent = 'ATIVADO (Pausa às 00:00)';
                badge.className = 'text-xs font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
                desc.textContent = 'Modo padrão ativo: usuários do plano Grátis pausam automaticamente à meia-noite e precisam reativar no aplicativo.';
                btn.textContent = 'Desativar Pausamento Automático';
                btn.className = 'px-5 py-2.5 rounded-xl font-semibold text-sm bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-lg shadow-amber-500/15 transition whitespace-nowrap';
            } else {
                badge.textContent = 'DESATIVADO (24h Contínuo)';
                badge.className = 'text-xs font-bold px-2.5 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/40';
                desc.textContent = 'Pausamento automático desligado: os contatos continuam sendo distribuídos normalmente após a meia-noite sem pausar.';
                btn.textContent = 'Ativar Pausamento Automático';
                btn.className = 'px-5 py-2.5 rounded-xl font-semibold text-sm bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-lg shadow-emerald-500/15 transition whitespace-nowrap';
            }
        }

        async function toggleGlobalAutoPause() {
            const btn = document.getElementById('toggleAutoPauseBtn');
            const targetState = !currentAutoPauseEnabled;
            btn.disabled = true;
            btn.textContent = 'Salvando...';
            try {
                const res = await adminFetch('/admin/settings/auto-pause/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: targetState })
                });
                const data = await res.json();
                if (res.ok) {
                    renderAutoPauseControl(data.auto_midnight_pause_enabled);
                    loadMetrics();
                    loadUsers();
                } else {
                    alert(data.detail || 'Não foi possível alterar o pausamento automático.');
                    renderAutoPauseControl(currentAutoPauseEnabled);
                }
            } catch (e) {
                alert('Erro de conexão ao atualizar configuração.');
                renderAutoPauseControl(currentAutoPauseEnabled);
            }
        }

        let adsConfigLoadedOnce = false;

        function setAdsIntervalPreset(value) {
            const input = document.getElementById('adsIntervalInput');
            if (input) input.value = value;
        }

        function renderAdsControl(settings, forceSyncInputs = false) {
            if (!settings) return;
            const badge = document.getElementById('adsStatusBadge');
            const saveBtn = document.getElementById('saveAdsBtn');
            const enabledEl = document.getElementById('adsEnabledToggle');
            const bannerEl = document.getElementById('adsBannerToggle');
            const interstitialEl = document.getElementById('adsInterstitialToggle');
            const intervalEl = document.getElementById('adsIntervalInput');

            if (saveBtn) saveBtn.disabled = false;

            if (!adsConfigLoadedOnce || forceSyncInputs) {
                if (enabledEl) enabledEl.checked = Boolean(settings.ads_enabled);
                if (bannerEl) bannerEl.checked = Boolean(settings.ads_banner_enabled);
                if (interstitialEl) interstitialEl.checked = Boolean(settings.ads_interstitial_enabled);
                if (intervalEl) intervalEl.value = Number(settings.ads_interstitial_interval || 4);
                adsConfigLoadedOnce = true;
            }

            if (badge) {
                if (!settings.ads_enabled) {
                    badge.textContent = 'DESATIVADOS';
                    badge.className = 'text-xs font-bold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40';
                } else {
                    const parts = [];
                    if (settings.ads_banner_enabled) parts.push('Banner');
                    if (settings.ads_interstitial_enabled) parts.push(`Tela Cheia a cada ${settings.ads_interstitial_interval}x`);
                    badge.textContent = parts.length > 0 ? `ATIVOS (${parts.join(' + ')})` : 'ATIVOS (Sem formato)';
                    badge.className = 'text-xs font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
                }
            }
        }

        async function saveAdsSettings() {
            const saveBtn = document.getElementById('saveAdsBtn');
            const feedback = document.getElementById('adsSaveFeedback');
            const adsEnabled = document.getElementById('adsEnabledToggle').checked;
            const adsBannerEnabled = document.getElementById('adsBannerToggle').checked;
            const adsInterstitialEnabled = document.getElementById('adsInterstitialToggle').checked;
            const rawInterval = parseInt(document.getElementById('adsIntervalInput').value || '4', 10);
            const adsInterstitialInterval = Math.max(1, Math.min(50, isNaN(rawInterval) ? 4 : rawInterval));
            document.getElementById('adsIntervalInput').value = adsInterstitialInterval;

            saveBtn.disabled = true;
            saveBtn.textContent = 'Salvando...';
            if (feedback) feedback.classList.add('hidden');

            try {
                const res = await adminFetch('/admin/settings/ads', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ads_enabled: adsEnabled,
                        ads_banner_enabled: adsBannerEnabled,
                        ads_interstitial_enabled: adsInterstitialEnabled,
                        ads_interstitial_interval: adsInterstitialInterval
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    renderAdsControl(data.ads_settings, true);
                    if (feedback) {
                        feedback.className = 'rounded-xl px-4 py-2.5 text-xs font-medium bg-emerald-500/15 border border-emerald-500/40 text-emerald-200';
                        feedback.textContent = data.message || 'Configurações de anúncios salvas com sucesso!';
                        feedback.classList.remove('hidden');
                    }
                } else {
                    if (feedback) {
                        feedback.className = 'rounded-xl px-4 py-2.5 text-xs font-medium bg-rose-500/15 border border-rose-500/40 text-rose-200';
                        feedback.textContent = data.detail || 'Não foi possível salvar as configurações de anúncios.';
                        feedback.classList.remove('hidden');
                    }
                }
            } catch (e) {
                if (feedback) {
                    feedback.className = 'rounded-xl px-4 py-2.5 text-xs font-medium bg-rose-500/15 border border-rose-500/40 text-rose-200';
                    feedback.textContent = 'Erro de conexão ao salvar configurações de anúncios.';
                    feedback.classList.remove('hidden');
                }
            } finally {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Salvar Configuração de Anúncios';
            }
        }

        async function loadMetrics() {
            try {
                const res = await adminFetch('/admin/metrics');
                const data = await res.json();
                document.getElementById('totalUsers').textContent = data.total_users;
                document.getElementById('activeUsersRatio').textContent = `${data.active_users} ativos na rede`;
                document.getElementById('premiumUsers').textContent = data.premium_users || 0;
                document.getElementById('todayExchanges').textContent = data.today_exchanges;
                document.getElementById('totalExchanges').textContent = `Total geral: ${data.total_exchanges}`;
                document.getElementById('avgReciprocity').textContent = data.avg_reciprocity.toFixed(2);
                document.getElementById('pendingReports').textContent = data.pending_reports;
                if (typeof data.auto_midnight_pause_enabled === 'boolean') {
                    renderAutoPauseControl(data.auto_midnight_pause_enabled);
                }
                if (data.ads_settings) {
                    renderAdsControl(data.ads_settings, false);
                }
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

        let currentUsersPage = 1;
        let usersPageSize = 50;
        let totalUsersCount = 0;
        let totalUsersPages = 1;

        function showUsersBulkFeedback(isOk, message) {
            const box = document.getElementById('usersBulkFeedback');
            if (!box) return;
            box.textContent = message;
            box.className = isOk
                ? 'mb-4 rounded-xl px-4 py-2.5 text-sm border bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'mb-4 rounded-xl px-4 py-2.5 text-sm border bg-rose-500/15 border-rose-500/40 text-rose-300';
        }

        function updateUsersPaginationControls(renderedCount) {
            totalUsersPages = Math.max(1, Math.ceil(totalUsersCount / usersPageSize));
            if (currentUsersPage > totalUsersPages) {
                currentUsersPage = totalUsersPages;
            }
            const infoEl = document.getElementById('usersPaginationInfo');
            const indicatorEl = document.getElementById('usersPageIndicator');
            const btnFirst = document.getElementById('btnUsersFirst');
            const btnPrev = document.getElementById('btnUsersPrev');
            const btnNext = document.getElementById('btnUsersNext');
            const btnLast = document.getElementById('btnUsersLast');

            if (totalUsersCount === 0 || renderedCount === 0) {
                if (infoEl) infoEl.textContent = 'Mostrando 0 de 0 usuários';
            } else {
                const startItem = (currentUsersPage - 1) * usersPageSize + 1;
                const endItem = Math.min(startItem + renderedCount - 1, totalUsersCount);
                if (infoEl) infoEl.textContent = `Mostrando ${startItem}–${endItem} de ${totalUsersCount} usuários`;
            }

            if (indicatorEl) indicatorEl.textContent = `Página ${currentUsersPage} de ${totalUsersPages}`;
            if (btnFirst) btnFirst.disabled = currentUsersPage <= 1;
            if (btnPrev) btnPrev.disabled = currentUsersPage <= 1;
            if (btnNext) btnNext.disabled = currentUsersPage >= totalUsersPages;
            if (btnLast) btnLast.disabled = currentUsersPage >= totalUsersPages;
        }

        function searchUsersFromStart() {
            currentUsersPage = 1;
            loadUsers();
        }

        function changeUsersPageSize() {
            const sel = document.getElementById('usersPageSizeSelect');
            usersPageSize = Math.max(10, Math.min(200, Number(sel ? sel.value : 50) || 50));
            currentUsersPage = 1;
            loadUsers();
        }

        function goToUsersPage(targetPage) {
            const safePage = Math.max(1, Math.min(totalUsersPages, Number(targetPage) || 1));
            if (safePage === currentUsersPage) return;
            currentUsersPage = safePage;
            loadUsers();
            const tableEl = document.getElementById('userTableBody');
            if (tableEl) {
                tableEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        }

        async function bulkPauseAllUsers() {
            if (!confirm('Tem certeza que deseja PAUSAR TODOS os usuários ativos da rede agora?\\n\\nUsuários bloqueados não serão alterados.')) {
                return;
            }
            const pauseBtn = document.getElementById('btnBulkPauseAll');
            const activateBtn = document.getElementById('btnBulkActivateAll');
            if (pauseBtn) { pauseBtn.disabled = true; pauseBtn.textContent = 'Pausando...'; }
            if (activateBtn) activateBtn.disabled = true;
            try {
                const res = await adminFetch('/admin/users/bulk-pause', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scope: 'all' })
                });
                const data = await res.json();
                if (!res.ok) {
                    showUsersBulkFeedback(false, data.detail || 'Não foi possível pausar os usuários.');
                    return;
                }
                showUsersBulkFeedback(true, data.message || 'Usuários pausados com sucesso.');
                loadUsers();
                loadMetrics();
                loadPushSummary();
            } catch (e) {
                showUsersBulkFeedback(false, 'Erro de conexão ao pausar todos os usuários.');
            } finally {
                if (pauseBtn) { pauseBtn.disabled = false; pauseBtn.textContent = '⏸ Pausar Todos'; }
                if (activateBtn) activateBtn.disabled = false;
            }
        }

        async function bulkActivateAllUsers() {
            if (!confirm('Tem certeza que deseja ATIVAR TODOS os usuários pausados da rede agora?\\n\\nUsuários bloqueados continuam bloqueados.')) {
                return;
            }
            const pauseBtn = document.getElementById('btnBulkPauseAll');
            const activateBtn = document.getElementById('btnBulkActivateAll');
            if (activateBtn) { activateBtn.disabled = true; activateBtn.textContent = 'Ativando...'; }
            if (pauseBtn) pauseBtn.disabled = true;
            try {
                const res = await adminFetch('/admin/users/bulk-activate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scope: 'all' })
                });
                const data = await res.json();
                if (!res.ok) {
                    showUsersBulkFeedback(false, data.detail || 'Não foi possível ativar os usuários.');
                    return;
                }
                showUsersBulkFeedback(true, data.message || 'Usuários ativados com sucesso.');
                loadUsers();
                loadMetrics();
                loadPushSummary();
            } catch (e) {
                showUsersBulkFeedback(false, 'Erro de conexão ao ativar todos os usuários.');
            } finally {
                if (activateBtn) { activateBtn.disabled = false; activateBtn.textContent = '▶ Ativar Todos'; }
                if (pauseBtn) pauseBtn.disabled = false;
            }
        }

        async function loadUsers() {
            const search = (document.getElementById('searchInput')?.value || '').trim();
            const status = (document.getElementById('userStatusFilter')?.value || 'all').trim();
            const tbody = document.getElementById('userTableBody');
            const offset = (currentUsersPage - 1) * usersPageSize;
            try {
                const res = await adminFetch(
                    `/admin/users?search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}&limit=${usersPageSize}&offset=${offset}`
                );
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                const headerTotal = Number(res.headers.get('X-Total-Count'));
                const users = await res.json();
                if (!Array.isArray(users)) {
                    throw new Error('Resposta inválida ao listar usuários');
                }
                totalUsersCount = Number.isFinite(headerTotal) && headerTotal >= 0 ? headerTotal : users.length;
                if (users.length === 0 && totalUsersCount > 0 && currentUsersPage > 1) {
                    currentUsersPage = Math.max(1, Math.ceil(totalUsersCount / usersPageSize));
                    return loadUsers();
                }
                updateUsersPaginationControls(users.length);
                if (!search && status === 'all' && currentUsersPage === 1) {
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
                    const planBadgeHtml = (() => {
                        if (!u.is_premium) {
                            return '<span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-700 text-slate-300">Grátis</span>';
                        }
                        if (!u.premium_expires_at) {
                            return `
                                <div class="flex flex-col items-start gap-0.5">
                                    <span class="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50">★ PREMIUM</span>
                                    <span class="text-[11px] text-amber-200/80 font-medium">Vitalício</span>
                                </div>`;
                        }
                        const expText = formatPremiumExpiryBr(u.premium_expires_at);
                        const daysLeft = u.premium_days_left;
                        const urgentCls = (daysLeft != null && daysLeft <= 5) ? 'text-rose-300' : 'text-emerald-300/90';
                        const daysLabel = daysLeft != null ? ` (${daysLeft}d)` : '';
                        return `
                            <div class="flex flex-col items-start gap-0.5">
                                <span class="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50">★ PREMIUM</span>
                                <span class="text-[11px] ${urgentCls}">Até ${escapeHtml(expText)}${escapeHtml(daysLabel)}</span>
                            </div>`;
                    })();
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
                            ${planBadgeHtml}
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
                            <button onclick="openPremiumModal(${u.id})" class="text-xs px-2.5 py-1 rounded font-semibold ${u.is_premium ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40' : 'bg-amber-600 hover:bg-amber-500 text-slate-950'} transition">
                                ${u.is_premium ? '★ Alterar / Remover' : '★ Tornar Premium'}
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
                window._lastLoadedUsersMap = Object.fromEntries(users.map(u => [u.id, u]));
            } catch(e) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-rose-400">Erro ao buscar dados.</td></tr>';
            }
        }

        let selectedPremiumUserId = null;

        function formatPremiumExpiryBr(isoUtc) {
            if (!isoUtc) return 'Vitalício';
            try {
                const raw = isoUtc.endsWith('Z') ? isoUtc : `${isoUtc}Z`;
                const dt = new Date(raw);
                if (isNaN(dt.getTime())) return isoUtc.slice(0, 10);
                return dt.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
            } catch (_) {
                return isoUtc.slice(0, 10);
            }
        }

        function openPremiumModal(userId) {
            const user = (window._lastLoadedUsersMap || {})[userId];
            if (!user) return;
            selectedPremiumUserId = userId;
            const infoEl = document.getElementById('premiumModalUserInfo');
            const statusEl = document.getElementById('premiumModalCurrentStatus');
            const removeBtn = document.getElementById('btnModalRemovePremium');
            const dateInput = document.getElementById('premiumCustomDateInput');

            if (infoEl) {
                infoEl.textContent = `${user.name || 'Participante'} — ${user.phone_e164 || ''}`;
            }
            if (statusEl) {
                if (user.is_premium) {
                    const expLabel = user.premium_expires_at
                        ? `★ Premium válido até ${formatPremiumExpiryBr(user.premium_expires_at)}`
                        : '★ Premium Vitalício (sem vencimento)';
                    statusEl.textContent = `Status atual: ${expLabel}`;
                } else {
                    statusEl.textContent = 'Status atual: Plano Grátis';
                }
            }
            if (removeBtn) {
                if (user.is_premium) {
                    removeBtn.classList.remove('hidden');
                } else {
                    removeBtn.classList.add('hidden');
                }
            }
            if (dateInput) {
                const defaultDate = new Date(Date.now() + 30 * 86400000);
                dateInput.min = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
                dateInput.value = user.premium_expires_at
                    ? user.premium_expires_at.slice(0, 10)
                    : defaultDate.toISOString().slice(0, 10);
            }
            const modal = document.getElementById('premiumPlanModal');
            if (modal) modal.classList.remove('hidden');
        }

        function closePremiumModal() {
            selectedPremiumUserId = null;
            const modal = document.getElementById('premiumPlanModal');
            if (modal) modal.classList.add('hidden');
        }

        async function applyPremiumDuration(duration) {
            if (!selectedPremiumUserId) return;
            const payload = { duration };
            if (duration === 'custom') {
                const dateVal = (document.getElementById('premiumCustomDateInput')?.value || '').trim();
                if (!dateVal) {
                    alert('Selecione uma data de validade primeiro.');
                    return;
                }
                payload.expires_at = dateVal;
            }
            if (duration === 'remove') {
                if (!confirm('Deseja remover o Premium deste usuário e retorná-lo para o plano Grátis?')) {
                    return;
                }
            }

            const buttons = document.querySelectorAll('.premium-dur-btn');
            buttons.forEach(b => { b.disabled = true; });
            try {
                const res = await adminFetch(`/admin/users/${selectedPremiumUserId}/premium`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) {
                    alert(data.detail || 'Não foi possível atualizar o plano Premium.');
                    return;
                }
                closePremiumModal();
                showUsersBulkFeedback(true, data.message || 'Plano Premium atualizado!');
                loadUsers();
                loadMetrics();
                loadPushSummary();
            } catch (e) {
                alert('Erro de conexão ao atualizar o plano Premium.');
            } finally {
                buttons.forEach(b => { b.disabled = false; });
            }
        }

        async function togglePause(id) {
            try {
                const res = await adminFetch(`/admin/users/${id}/toggle-pause`, { method: 'POST' });
                if (!res.ok) return;
                loadUsers();
                loadMetrics();
                loadPushSummary();
            } catch (e) {
                console.error(e);
            }
        }

        async function toggleActive(id) {
            try {
                const res = await adminFetch(`/admin/users/${id}/toggle-active`, { method: 'POST' });
                if (!res.ok) return;
                loadUsers();
                loadMetrics();
                loadPushSummary();
            } catch (e) {
                console.error(e);
            }
        }

        function scrollToReportsSection() {
            const section = document.getElementById('reportsSection');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }

        function showReportsFeedback(isOk, message) {
            const box = document.getElementById('reportsFeedback');
            if (!box) return;
            box.className = isOk
                ? 'rounded-xl px-4 py-2.5 text-xs font-medium bg-emerald-500/15 border border-emerald-500/40 text-emerald-200'
                : 'rounded-xl px-4 py-2.5 text-xs font-medium bg-rose-500/15 border border-rose-500/40 text-rose-200';
            box.textContent = message;
            box.classList.remove('hidden');
        }

        async function loadReports() {
            const tbody = document.getElementById('reportsTableBody');
            const filterEl = document.getElementById('reportsStatusFilter');
            const badgeEl = document.getElementById('reportsSectionBadge');
            const status = filterEl ? filterEl.value : 'pending';
            try {
                const res = await adminFetch(`/admin/reports?status=${encodeURIComponent(status)}`);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const rows = await res.json();
                const pendingCount = rows.filter(r => r.status === 'pending').length;
                if (badgeEl) {
                    if (status === 'pending') {
                        badgeEl.textContent = `${rows.length} pendente(s)`;
                    } else {
                        badgeEl.textContent = `${rows.length} registro(s) • ${pendingCount} pendente(s)`;
                    }
                }
                if (!rows.length) {
                    const emptyText = status === 'pending'
                        ? 'Nenhuma denúncia pendente no momento.'
                        : 'Nenhuma denúncia encontrada neste filtro.';
                    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">${emptyText}</td></tr>`;
                    return;
                }
                tbody.innerHTML = rows.map(r => {
                    const dt = r.created_at ? new Date(r.created_at + 'Z').toLocaleString('pt-BR') : '--';
                    const statusBadge = r.status === 'pending'
                        ? '<span class="inline-block px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">Pendente</span>'
                        : r.status === 'dismissed'
                            ? '<span class="inline-block px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-700 text-slate-300">Descartada</span>'
                            : '<span class="inline-block px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">Resolvida</span>';
                    const userStateBadge = !r.reported_is_active
                        ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">Bloqueado</span>'
                        : r.reported_is_paused
                            ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300">Pausado</span>'
                            : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">Ativo</span>';
                    const actionsHtml = r.status === 'pending'
                        ? `
                            <button onclick="resolveReport(${r.id}, 'ban')" class="text-[11px] px-2.5 py-1 rounded-lg bg-rose-600/90 hover:bg-rose-500 text-white font-semibold transition">Bloquear</button>
                            <button onclick="resolveReport(${r.id}, 'pause')" class="text-[11px] px-2.5 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-semibold transition">Pausar</button>
                            <button onclick="resolveReport(${r.id}, 'resolve')" class="text-[11px] px-2.5 py-1 rounded-lg bg-emerald-600/90 hover:bg-emerald-500 text-white font-semibold transition">Resolver</button>
                            <button onclick="resolveReport(${r.id}, 'dismiss')" class="text-[11px] px-2.5 py-1 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition">Descartar</button>
                          `
                        : `
                            <button onclick="resolveReport(${r.id}, 'reopen')" class="text-[11px] px-2.5 py-1 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition">Reabrir</button>
                            <button onclick="deleteReport(${r.id})" class="text-[11px] px-2.5 py-1 rounded-lg bg-rose-900/50 hover:bg-rose-900 text-rose-300 transition">Excluir</button>
                          `;
                    return `
                        <tr class="hover:bg-slate-700/30 transition ${r.status === 'pending' ? 'bg-amber-500/5' : ''}">
                            <td class="py-3 px-3 whitespace-nowrap space-y-1">
                                <div>${statusBadge}</div>
                                <div class="text-[11px] text-slate-400">${escapeHtml(dt)}</div>
                            </td>
                            <td class="py-3 px-3">
                                <div class="flex items-center gap-1.5 font-semibold text-white">
                                    <span>${escapeHtml(r.reported_name)}</span>
                                    ${userStateBadge}
                                </div>
                                <div class="text-[11px] font-mono text-emerald-400">${escapeHtml(r.reported_phone || 'Sem telefone')}</div>
                            </td>
                            <td class="py-3 px-3 max-w-sm">
                                <div class="font-semibold text-amber-200">${escapeHtml(r.reason)}</div>
                                <div class="text-slate-400 whitespace-pre-wrap break-words mt-0.5">${escapeHtml(r.details || 'Sem detalhes adicionais.')}</div>
                            </td>
                            <td class="py-3 px-3 whitespace-nowrap">
                                <div class="text-slate-200 font-medium">${escapeHtml(r.reporter_name)}</div>
                                <div class="text-[11px] font-mono text-slate-400">${escapeHtml(r.reporter_phone || '')}</div>
                            </td>
                            <td class="py-3 px-3 text-right space-x-1 whitespace-nowrap">
                                ${actionsHtml}
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (e) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center py-6 text-rose-400">Erro ao carregar denúncias.</td></tr>';
            }
        }

        async function resolveReport(reportId, action) {
            if (action === 'ban' && !confirm('Tem certeza que deseja BLOQUEAR este usuário denunciado e encerrar a denúncia?')) {
                return;
            }
            try {
                const res = await adminFetch(`/admin/reports/${reportId}/resolve?action=${encodeURIComponent(action)}`, {
                    method: 'POST'
                });
                const data = await res.json();
                if (!res.ok) {
                    showReportsFeedback(false, data.detail || 'Não foi possível processar a denúncia.');
                    return;
                }
                showReportsFeedback(true, data.message || 'Denúncia atualizada com sucesso.');
                loadReports();
                loadMetrics();
                loadUsers();
            } catch (e) {
                showReportsFeedback(false, 'Erro de conexão ao processar denúncia.');
            }
        }

        async function deleteReport(reportId) {
            if (!confirm('Deseja excluir permanentemente este registro de denúncia?')) {
                return;
            }
            try {
                const res = await adminFetch(`/admin/reports/${reportId}`, {
                    method: 'DELETE'
                });
                const data = await res.json();
                if (!res.ok) {
                    showReportsFeedback(false, data.detail || 'Não foi possível excluir a denúncia.');
                    return;
                }
                showReportsFeedback(true, data.message || 'Denúncia excluída.');
                loadReports();
                loadMetrics();
            } catch (e) {
                showReportsFeedback(false, 'Erro de conexão ao excluir denúncia.');
            }
        }

        // Init (painel já autenticado via cookie HttpOnly + CSRF)
        loadMetrics();
        loadReports();
        loadUsers();
        loadPushSummary();
        loadPushHistory();
        setInterval(loadMetrics, 10000);
    </script>
</body>
</html>
    """
    html = html.replace("__CSRF_TOKEN__", csrf_token)
    return HTMLResponse(content=html, headers=_NO_CACHE_HEADERS)
