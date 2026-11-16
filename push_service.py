import asyncio
import base64
import datetime
import json
import os
from typing import Dict, List, Optional, Tuple

from sqlalchemy import desc, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog, DeviceToken, PushCampaign, User

_firebase_init_error: Optional[str] = None
_firebase_app_initialized = False


def ensure_firebase_initialized() -> Tuple[bool, Optional[str]]:
    """Inicializa Firebase Admin SDK de forma segura usando variável de ambiente no Railway."""
    global _firebase_app_initialized, _firebase_init_error

    if _firebase_app_initialized:
        return True, None

    try:
        import firebase_admin
        from firebase_admin import credentials

        if firebase_admin._apps:
            _firebase_app_initialized = True
            _firebase_init_error = None
            return True, None

        raw_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

        if raw_json:
            if not raw_json.startswith("{"):
                # Suporte opcional a base64
                raw_json = base64.b64decode(raw_json).decode("utf-8")
            service_info = json.loads(raw_json)
            cred = credentials.Certificate(service_info)
            firebase_admin.initialize_app(cred)
        elif cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        else:
            _firebase_init_error = (
                "Credencial do Firebase não configurada no servidor. "
                "Defina a variável FIREBASE_SERVICE_ACCOUNT_JSON no Railway."
            )
            return False, _firebase_init_error

        _firebase_app_initialized = True
        _firebase_init_error = None
        return True, None
    except Exception as exc:
        _firebase_init_error = f"Falha ao inicializar Firebase Admin SDK: {exc}"
        return False, _firebase_init_error


async def register_device_token(
    db: AsyncSession,
    fcm_token: str,
    user_id: Optional[int] = None,
    device_platform: str = "android"
) -> DeviceToken:
    clean_token = fcm_token.strip()
    now = datetime.datetime.utcnow()

    valid_user_id: Optional[int] = None
    if user_id is not None and user_id > 0:
        user = await db.get(User, user_id)
        if user is not None:
            valid_user_id = user.id

    res = await db.execute(select(DeviceToken).where(DeviceToken.fcm_token == clean_token))
    existing = res.scalars().first()

    if existing:
        existing.is_active = True
        existing.device_platform = (device_platform or "android")[:20]
        existing.last_seen_at = now
        if valid_user_id is not None:
            existing.user_id = valid_user_id
        await db.commit()
        await db.refresh(existing)
        return existing

    token_row = DeviceToken(
        fcm_token=clean_token,
        user_id=valid_user_id,
        device_platform=(device_platform or "android")[:20],
        is_active=True,
        last_seen_at=now,
        created_at=now,
    )
    db.add(token_row)
    await db.commit()
    await db.refresh(token_row)
    return token_row


async def get_tokens_for_audience(
    db: AsyncSession,
    audience: str,
    target_user_id: Optional[int] = None
) -> Tuple[List[DeviceToken], str]:
    now_label = ""
    if audience == "test":
        if not target_user_id:
            return [], "Nenhum usuário selecionado"
        user = await db.get(User, target_user_id)
        label = f"{user.name} ({user.phone_e164})" if user else f"Usuário #{target_user_id}"
        stmt = (
            select(DeviceToken)
            .where(DeviceToken.is_active == True, DeviceToken.user_id == target_user_id)
            .order_by(desc(DeviceToken.last_seen_at))
        )
        rows = (await db.execute(stmt)).scalars().all()
        return list(rows), label

    if audience == "premium":
        stmt = (
            select(DeviceToken)
            .join(User, DeviceToken.user_id == User.id)
            .where(
                DeviceToken.is_active == True,
                User.is_active == True,
                User.is_premium == True,
            )
        )
        rows = (await db.execute(stmt)).scalars().all()
        return list(rows), "Somente usuários Premium"

    if audience == "free":
        stmt = (
            select(DeviceToken)
            .outerjoin(User, DeviceToken.user_id == User.id)
            .where(
                DeviceToken.is_active == True,
                or_(
                    DeviceToken.user_id.is_(None),
                    (User.is_active == True) & (User.is_premium == False),
                ),
            )
        )
        rows = (await db.execute(stmt)).scalars().all()
        return list(rows), "Somente usuários Grátis"

    # Padrão: all
    stmt = (
        select(DeviceToken)
        .outerjoin(User, DeviceToken.user_id == User.id)
        .where(
            DeviceToken.is_active == True,
            or_(
                DeviceToken.user_id.is_(None),
                User.is_active == True,
            ),
        )
    )
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows), "Todos os usuários"


async def get_audience_counts(db: AsyncSession) -> Dict[str, int]:
    all_tokens, _ = await get_tokens_for_audience(db, "all")
    free_tokens, _ = await get_tokens_for_audience(db, "free")
    premium_tokens, _ = await get_tokens_for_audience(db, "premium")
    return {
        "all": len(all_tokens),
        "free": len(free_tokens),
        "premium": len(premium_tokens),
    }


def _send_multicast_chunk(tokens: List[str], title: str, body: str, audience: str):
    from firebase_admin import messaging

    message = messaging.MulticastMessage(
        tokens=tokens,
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        android=messaging.AndroidConfig(
            priority="high",
            notification=messaging.AndroidNotification(
                channel_id="statuszap_general",
                title=title,
                body=body,
                sound="default",
            ),
        ),
        data={
            "target_screen": "home",
            "title": title,
            "body": body,
            "audience": audience,
        },
    )
    return messaging.send_each_for_multicast(message)


async def send_push_campaign(
    db: AsyncSession,
    title: str,
    body: str,
    audience: str = "all",
    target_user_id: Optional[int] = None,
) -> Dict:
    clean_title = title.strip()
    clean_body = body.strip()
    norm_audience = audience if audience in {"all", "free", "premium", "test"} else "all"

    token_rows, target_label = await get_tokens_for_audience(db, norm_audience, target_user_id)
    unique_tokens: List[str] = []
    seen = set()
    for row in token_rows:
        if row.fcm_token not in seen:
            seen.add(row.fcm_token)
            unique_tokens.append(row.fcm_token)

    total_targeted = len(unique_tokens)

    if total_targeted == 0:
        campaign = PushCampaign(
            title=clean_title,
            body=clean_body,
            audience=norm_audience,
            target_user_id=target_user_id,
            target_user_label=target_label,
            total_targeted=0,
            firebase_accepted=0,
            firebase_errors=0,
            error_summary="Nenhum dispositivo com token FCM ativo encontrado para este público.",
            created_at=datetime.datetime.utcnow(),
        )
        db.add(campaign)
        await db.commit()
        await db.refresh(campaign)
        return {
            "campaign_id": campaign.id,
            "audience": norm_audience,
            "target_label": target_label,
            "total_targeted": 0,
            "firebase_accepted": 0,
            "firebase_errors": 0,
            "error_summary": campaign.error_summary,
            "created_at": campaign.created_at.isoformat(),
        }

    ok, init_err = ensure_firebase_initialized()
    if not ok:
        raise RuntimeError(init_err or "Firebase Admin SDK não configurado.")

    accepted_count = 0
    error_count = 0
    invalid_tokens: List[str] = []
    error_codes: Dict[str, int] = {}

    # FCM Multicast aceita até 500 tokens por chamada
    chunk_size = 500
    for idx in range(0, total_targeted, chunk_size):
        chunk = unique_tokens[idx : idx + chunk_size]
        batch_response = await asyncio.to_thread(_send_multicast_chunk, chunk, clean_title, clean_body, norm_audience)
        accepted_count += int(batch_response.success_count)
        error_count += int(batch_response.failure_count)

        for token_str, resp in zip(chunk, batch_response.responses):
            if not resp.success and resp.exception is not None:
                err = resp.exception
                code = getattr(err, "code", None) or err.__class__.__name__
                code_str = str(code)
                error_codes[code_str] = error_codes.get(code_str, 0) + 1
                upper_code = code_str.upper()
                if "UNREGISTERED" in upper_code or "NOT_FOUND" in upper_code or "INVALID_ARGUMENT" in upper_code or "SENDER_ID_MISMATCH" in upper_code:
                    invalid_tokens.append(token_str)

    if invalid_tokens:
        await db.execute(
            update(DeviceToken)
            .where(DeviceToken.fcm_token.in_(invalid_tokens))
            .values(is_active=False)
        )

    error_summary = ""
    if error_codes:
        parts = [f"{k}: {v}" for k, v in sorted(error_codes.items())]
        error_summary = "; ".join(parts)
        if invalid_tokens:
            error_summary += f" ({len(invalid_tokens)} token(s) inválido(s) desativado(s))"

    now = datetime.datetime.utcnow()
    campaign = PushCampaign(
        title=clean_title,
        body=clean_body,
        audience=norm_audience,
        target_user_id=target_user_id,
        target_user_label=target_label,
        total_targeted=total_targeted,
        firebase_accepted=accepted_count,
        firebase_errors=error_count,
        error_summary=error_summary,
        created_at=now,
    )
    db.add(campaign)
    db.add(
        AuditLog(
            user_id=target_user_id,
            action="ADMIN_PUSH_TEST" if norm_audience == "test" else "ADMIN_PUSH_BROADCAST",
            timestamp=now,
            details=(
                f"Push '{clean_title}' [{norm_audience}] -> alvo={total_targeted}, "
                f"aceitos_fcm={accepted_count}, erros_fcm={error_count}."
            ),
        )
    )
    await db.commit()
    await db.refresh(campaign)

    return {
        "campaign_id": campaign.id,
        "audience": norm_audience,
        "target_label": target_label,
        "total_targeted": total_targeted,
        "firebase_accepted": accepted_count,
        "firebase_errors": error_count,
        "error_summary": error_summary,
        "created_at": campaign.created_at.isoformat(),
    }
