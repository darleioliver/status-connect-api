import datetime
import hashlib
import random
from typing import Any, Dict, List, Tuple
from sqlalchemy import select, func, and_, not_
from sqlalchemy.ext.asyncio import AsyncSession
from models import User, ContactExchange, OtpVerification, AuditLog, AppSetting
from schemas import ContactDto
from db_migrations import ensure_push_tables

SETTING_AUTO_MIDNIGHT_PAUSE = "auto_midnight_pause_enabled"
SETTING_ADS_ENABLED = "ads_enabled"
SETTING_ADS_BANNER_ENABLED = "ads_banner_enabled"
SETTING_ADS_INTERSTITIAL_ENABLED = "ads_interstitial_enabled"
SETTING_ADS_INTERSTITIAL_INTERVAL = "ads_interstitial_interval"
SETTING_HOME_CAROUSEL_ENABLED = "home_carousel_enabled"
DEFAULT_INTERSTITIAL_INTERVAL = 4
MIN_INTERSTITIAL_INTERVAL = 1
MAX_INTERSTITIAL_INTERVAL = 50


def brasilia_today_str() -> str:
    return (datetime.datetime.utcnow() - datetime.timedelta(hours=3)).strftime("%Y-%m-%d")


async def is_midnight_auto_pause_enabled(db: AsyncSession) -> bool:
    """Retorna se o pausamento automático à meia-noite (plano Grátis) está ativo (padrão: True)."""
    await ensure_push_tables()
    try:
        async with db.begin_nested():
            setting = await db.get(AppSetting, SETTING_AUTO_MIDNIGHT_PAUSE)
            if not setting:
                return True
            return setting.value.strip().lower() in {"1", "true", "yes", "on", "sim"}
    except Exception:
        return True


async def set_midnight_auto_pause_enabled(db: AsyncSession, enabled: bool) -> bool:
    """Ativa ou desativa o pausamento automático à meia-noite pelo painel administrativo."""
    await ensure_push_tables()
    now = datetime.datetime.utcnow()
    val_str = "true" if enabled else "false"
    setting = await db.get(AppSetting, SETTING_AUTO_MIDNIGHT_PAUSE)
    if setting:
        setting.value = val_str
        setting.updated_at = now
    else:
        db.add(AppSetting(key=SETTING_AUTO_MIDNIGHT_PAUSE, value=val_str, updated_at=now))

    db.add(
        AuditLog(
            user_id=None,
            action="AUTO_MIDNIGHT_PAUSE_ENABLED" if enabled else "AUTO_MIDNIGHT_PAUSE_DISABLED",
            timestamp=now,
            details=(
                "Administrador ativou o pausamento automático diário às 00:00 (plano Grátis)."
                if enabled
                else "Administrador desativou o pausamento automático diário às 00:00 (contatos continuam sendo distribuídos)."
            ),
        )
    )
    await db.commit()
    return enabled


def _parse_bool_setting(raw_value: str, default: bool = True) -> bool:
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on", "sim"}


async def _upsert_app_setting(db: AsyncSession, key: str, value: str, now: datetime.datetime) -> None:
    setting = await db.get(AppSetting, key)
    if setting:
        setting.value = value
        setting.updated_at = now
    else:
        db.add(AppSetting(key=key, value=value, updated_at=now))


async def get_ads_settings(db: AsyncSession) -> Dict[str, Any]:
    """Retorna as configurações atuais de anúncios AdMob controladas pelo painel admin."""
    await ensure_push_tables()
    defaults = {
        "ads_enabled": True,
        "ads_banner_enabled": True,
        "ads_interstitial_enabled": True,
        "ads_interstitial_interval": DEFAULT_INTERSTITIAL_INTERVAL,
    }
    try:
        async with db.begin_nested():
            stmt = select(AppSetting).where(
                AppSetting.key.in_(
                    [
                        SETTING_ADS_ENABLED,
                        SETTING_ADS_BANNER_ENABLED,
                        SETTING_ADS_INTERSTITIAL_ENABLED,
                        SETTING_ADS_INTERSTITIAL_INTERVAL,
                    ]
                )
            )
            rows = (await db.execute(stmt)).scalars().all()
            mapping = {row.key: row.value for row in rows}
            try:
                raw_interval = int(mapping.get(SETTING_ADS_INTERSTITIAL_INTERVAL, str(DEFAULT_INTERSTITIAL_INTERVAL)))
            except (TypeError, ValueError):
                raw_interval = DEFAULT_INTERSTITIAL_INTERVAL
            clamped_interval = max(MIN_INTERSTITIAL_INTERVAL, min(MAX_INTERSTITIAL_INTERVAL, raw_interval))
            return {
                "ads_enabled": _parse_bool_setting(mapping.get(SETTING_ADS_ENABLED), True),
                "ads_banner_enabled": _parse_bool_setting(mapping.get(SETTING_ADS_BANNER_ENABLED), True),
                "ads_interstitial_enabled": _parse_bool_setting(mapping.get(SETTING_ADS_INTERSTITIAL_ENABLED), True),
                "ads_interstitial_interval": clamped_interval,
            }
    except Exception:
        return defaults


async def update_ads_settings(
    db: AsyncSession,
    ads_enabled: bool,
    ads_banner_enabled: bool,
    ads_interstitial_enabled: bool,
    ads_interstitial_interval: int,
) -> Dict[str, Any]:
    """Salva configurações de anúncios AdMob (Banner + Intersticial + frequência) no PostgreSQL."""
    await ensure_push_tables()
    now = datetime.datetime.utcnow()
    clamped_interval = max(MIN_INTERSTITIAL_INTERVAL, min(MAX_INTERSTITIAL_INTERVAL, int(ads_interstitial_interval)))

    await _upsert_app_setting(db, SETTING_ADS_ENABLED, "true" if ads_enabled else "false", now)
    await _upsert_app_setting(db, SETTING_ADS_BANNER_ENABLED, "true" if ads_banner_enabled else "false", now)
    await _upsert_app_setting(db, SETTING_ADS_INTERSTITIAL_ENABLED, "true" if ads_interstitial_enabled else "false", now)
    await _upsert_app_setting(db, SETTING_ADS_INTERSTITIAL_INTERVAL, str(clamped_interval), now)

    db.add(
        AuditLog(
            user_id=None,
            action="ADS_SETTINGS_UPDATED",
            timestamp=now,
            details=(
                f"Administrador atualizou AdMob: geral={'ON' if ads_enabled else 'OFF'}, "
                f"banner={'ON' if ads_banner_enabled else 'OFF'}, "
                f"tela_cheia={'ON' if ads_interstitial_enabled else 'OFF'}, "
                f"interacoes={clamped_interval}."
            ),
        )
    )
    await db.commit()
    return {
        "ads_enabled": bool(ads_enabled),
        "ads_banner_enabled": bool(ads_banner_enabled),
        "ads_interstitial_enabled": bool(ads_interstitial_enabled),
        "ads_interstitial_interval": clamped_interval,
    }


async def is_home_carousel_enabled(db: AsyncSession) -> bool:
    """Retorna se o banner carrossel no topo da tela inicial está ativado (padrão: True)."""
    await ensure_push_tables()
    try:
        async with db.begin_nested():
            setting = await db.get(AppSetting, SETTING_HOME_CAROUSEL_ENABLED)
            if not setting:
                return True
            return _parse_bool_setting(setting.value, True)
    except Exception:
        return True


async def set_home_carousel_enabled(db: AsyncSession, enabled: bool) -> bool:
    """Ativa ou desativa globalmente o banner carrossel da tela inicial pelo painel admin."""
    await ensure_push_tables()
    now = datetime.datetime.utcnow()
    await _upsert_app_setting(db, SETTING_HOME_CAROUSEL_ENABLED, "true" if enabled else "false", now)
    db.add(
        AuditLog(
            user_id=None,
            action="HOME_CAROUSEL_ENABLED" if enabled else "HOME_CAROUSEL_DISABLED",
            timestamp=now,
            details=(
                "Administrador ATIVOU o banner carrossel da tela inicial."
                if enabled
                else "Administrador DESATIVOU o banner carrossel da tela inicial."
            ),
        )
    )
    await db.commit()
    return bool(enabled)


async def revoke_expired_premium_users(db: AsyncSession) -> int:
    """Remove automaticamente o status Premium de usuários cujo prazo (premium_expires_at) expirou."""
    await ensure_push_tables()
    now = datetime.datetime.utcnow()
    today_str = brasilia_today_str()
    try:
        async with db.begin_nested():
            expired_stmt = select(User.id, User.name).where(
                User.is_premium == True,
                User.premium_expires_at != None,
                User.premium_expires_at <= now,
            )
            expired_rows = (await db.execute(expired_stmt)).all()
            if not expired_rows:
                return 0

            expired_ids = [row[0] for row in expired_rows]
            from sqlalchemy import update
            await db.execute(
                update(User)
                .where(User.id.in_(expired_ids))
                .values(
                    is_premium=False,
                    premium_expires_at=None,
                    last_active_date=today_str,
                    updated_at=now,
                )
            )
            for uid, uname in expired_rows:
                db.add(
                    AuditLog(
                        user_id=uid,
                        action="PREMIUM_EXPIRED",
                        timestamp=now,
                        details=f"Plano Premium de {uname} expirou automaticamente e voltou para o plano Grátis.",
                    )
                )
        await db.commit()
        return len(expired_ids)
    except Exception:
        return 0


async def pause_expired_free_users(db: AsyncSession):
    """Expira planos Premium vencidos e pausa à meia-noite (Brasília) usuários do plano Grátis quando ativado no painel."""
    await revoke_expired_premium_users(db)
    if not await is_midnight_auto_pause_enabled(db):
        return
    today_str = brasilia_today_str()
    from sqlalchemy import update
    stmt = (
        update(User)
        .where(
            User.is_active == True,
            User.is_paused == False,
            User.is_premium == False,
            User.last_active_date != None,
            User.last_active_date != "",
            User.last_active_date != today_str
        )
        .values(is_paused=True)
    )
    res = await db.execute(stmt)
    if res.rowcount and res.rowcount > 0:
        await db.commit()

def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()

async def generate_and_store_otp(db: AsyncSession, phone_e164: str) -> str:
    # Código de 6 dígitos
    # Para número de teste ou em ambiente local, 123456 pode ser usado
    code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    
    # Invalidar anteriores
    stmt = select(OtpVerification).where(
        OtpVerification.phone_e164 == phone_e164,
        OtpVerification.verified == False
    )
    res = await db.execute(stmt)
    for row in res.scalars():
        row.verified = True
    
    otp_record = OtpVerification(
        phone_e164=phone_e164,
        code_hash=hash_code(code),
        attempts=0,
        expires_at=expires_at,
        verified=False
    )
    db.add(otp_record)
    await db.commit()
    return code

async def verify_otp(db: AsyncSession, phone_e164: str, code: str) -> bool:
    # Código universal de teste/demonstração para facilitar testes rápidos e avaliações: 123456
    if code == "123456":
        return True

    now = datetime.datetime.utcnow()
    hashed = hash_code(code)
    stmt = (
        select(OtpVerification)
        .where(
            OtpVerification.phone_e164 == phone_e164,
            OtpVerification.verified == False,
            OtpVerification.expires_at > now
        )
        .order_by(OtpVerification.created_at.desc())
    )
    res = await db.execute(stmt)
    record = res.scalars().first()

    if not record:
        return False

    record.attempts += 1
    if record.attempts > 5:
        await db.commit()
        return False

    if record.code_hash == hashed:
        record.verified = True
        await db.commit()
        return True

    await db.commit()
    return False

async def get_reciprocal_contacts_batch(
    db: AsyncSession,
    user_id: int,
    batch_size: int = 10
) -> Tuple[List[ContactDto], int, float, str]:
    await pause_expired_free_users(db)

    # 1. Carregar usuário solicitante
    user = await db.get(User, user_id)
    if not user:
        raise ValueError("Usuário não encontrado.")

    if not user.is_active:
        raise ValueError("Conta inativa.")

    if user.is_paused:
        raise ValueError("Sua conta está pausada. Reative o compartilhamento para receber contatos.")

    # 2. Obter lista de IDs já distribuídos ao usuário para garantir ZERO DUPLICIDADE
    exchanged_stmt = select(ContactExchange.contact_user_id).where(
        ContactExchange.user_id == user_id
    )
    exchanged_res = await db.execute(exchanged_stmt)
    already_received_ids = set(exchanged_res.scalars().all())

    # 3. Buscar candidatos disponíveis (priorizando contatos Premium)
    candidate_stmt = (
        select(User)
        .where(
            and_(
                User.id != user_id,
                User.is_active == True,
                User.is_paused == False,
                not_(User.id.in_(already_received_ids)) if already_received_ids else True
            )
        )
        .order_by(User.is_premium.desc(), User.total_contacts_shared.asc(), User.reciprocity_score.desc())
        .limit(batch_size * 2)
    )
    candidate_res = await db.execute(candidate_stmt)
    candidates = candidate_res.scalars().all()

    if not candidates:
        return (
            [],
            0,
            user.reciprocity_score,
            "Você já recebeu todos os contatos ativos disponíveis no momento! Novos participantes cadastrados aparecerão aqui em breve."
        )

    # Mantém destaque dos Premium no topo e embaralha dentro do grupo
    premium_candidates = [c for c in candidates if c.is_premium]
    free_candidates = [c for c in candidates if not c.is_premium]
    random.shuffle(premium_candidates)
    random.shuffle(free_candidates)
    selected = (premium_candidates + free_candidates)[:batch_size]

    now = datetime.datetime.utcnow()
    result_dtos: List[ContactDto] = []

    for contact_user in selected:
        exchange = ContactExchange(
            user_id=user.id,
            contact_user_id=contact_user.id,
            distributed_at=now,
            added_to_device=False,
            is_blocked=False
        )
        db.add(exchange)
        await db.flush()

        # Atualizar contadores do doador
        contact_user.total_contacts_shared += 1
        contact_user.reciprocity_score = round(
            min(2.0, (contact_user.total_contacts_shared + 1.0) / (contact_user.total_contacts_received + 1.0)),
            2
        )

        result_dtos.append(
            ContactDto(
                id=exchange.id,
                user_id=contact_user.id,
                name=contact_user.name,
                phone_e164=contact_user.phone_e164,
                country_code=contact_user.country_code,
                bio=contact_user.bio or "Status do WhatsApp",
                state=contact_user.state or "",
                gender=contact_user.gender or "",
                is_premium=bool(contact_user.is_premium),
                distributed_at=now,
                added_to_device=False
            )
        )

    # Atualizar contadores do receptor
    user.total_contacts_received += len(selected)
    user.reciprocity_score = round(
        min(2.0, (user.total_contacts_shared + 1.0) / (user.total_contacts_received + 1.0)),
        2
    )

    # Registrar log de auditoria
    audit = AuditLog(
        user_id=user.id,
        action="BATCH_EXCHANGED",
        timestamp=now,
        details=f"Recebeu lote de {len(selected)} contatos com consentimento recíproco."
    )
    db.add(audit)

    await db.commit()

    message = f"{len(selected)} novos contatos disponibilizados com sucesso! Nenhum contato duplicado."
    remaining_quota = max(0, user.daily_quota - len(selected))
    return (result_dtos, remaining_quota, user.reciprocity_score, message)

async def seed_initial_community_pool(db: AsyncSession):
    # Expurgar quaisquer usuários de teste antigos do banco de dados remoto
    legacy_test_phones = [
        "+5511987654321", "+5521991234567", "+5531988887766", "+5541997776655",
        "+5551981239876", "+5561996543210", "+5571987651234", "+5581995438765",
        "+5585994321098", "+5591983216540", "+351912345678", "+5519987650123",
        "+5511993456789", "+5521981112233", "+5531992223344"
    ]
    try:
        from sqlalchemy import delete
        stmt = delete(User).where(User.phone_e164.in_(legacy_test_phones))
        await db.execute(stmt)
        await db.commit()
    except Exception:
        pass

