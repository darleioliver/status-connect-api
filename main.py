import datetime
import hashlib
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import engine, Base, get_db
from models import User, ContactExchange, OtpVerification, Report, AuditLog
from schemas import (
    OtpRequest, OtpVerifyRequest, UserRegisterRequest, UserResponse,
    ContactDto, ExchangeRequest, ExchangeBatchResponse, StatsResponse,
    PrivacyUpdateRequest, ReportRequest, MarkBatchAddedRequest
)
from exchange_service import (
    generate_and_store_otp, verify_otp, get_reciprocal_contacts_batch,
    seed_initial_community_pool
)
from admin import router as admin_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa as tabelas do banco no startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Popula contatos iniciais da comunidade se estiver vazio
    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        await seed_initial_community_pool(session)
    
    yield
    # Limpeza de conexões
    await engine.dispose()

app = FastAPI(
    title="StatusZap API — Troca Recíproca de Contatos",
    description="Backend oficial da plataforma de ampliação de audiência de Status do WhatsApp com conformidade LGPD e deduplicação estrita.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS liberado para o app Android e clientes web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)

@app.get("/api/v1/health", tags=["Sistema"])
async def health_check():
    return {
        "status": "healthy",
        "service": "StatusZap API",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

# --- OTP & Verificação Segura ---

@app.post("/api/v1/otp/request", tags=["Autenticação & OTP"])
async def request_otp(payload: OtpRequest, db: AsyncSession = Depends(get_db)):
    phone = payload.phone_e164
    
    # Proteção contra abuso: checa se gerou OTP nos últimos 60 segundos
    one_minute_ago = datetime.datetime.utcnow() - datetime.timedelta(seconds=60)
    recent_stmt = select(OtpVerification).where(
        OtpVerification.phone_e164 == phone,
        OtpVerification.created_at >= one_minute_ago
    )
    recent_res = await db.execute(recent_stmt)
    if recent_res.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Aguarde 60 segundos antes de solicitar um novo código de confirmação."
        )

    code = await generate_and_store_otp(db, phone)
    
    # Em produção, integra com gateway SMS/WhatsApp (ex: Z-API, Twilio).
    # Em teste/demonstração, o código '123456' é universalmente aceito.
    return {
        "success": True,
        "message": f"Código de confirmação enviado para {phone}. (Em ambiente de testes, utilize 123456 ou {code})",
        "phone_e164": phone,
        "cooldown_seconds": 60
    }

@app.post("/api/v1/otp/verify", tags=["Autenticação & OTP"])
async def verify_otp_endpoint(payload: OtpVerifyRequest, db: AsyncSession = Depends(get_db)):
    valid = await verify_otp(db, payload.phone_e164, payload.code)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de verificação incorreto ou expirado."
        )
    return {"success": True, "message": "Telefone verificado com sucesso."}

# --- Cadastro de Usuários (LGPD & Anti-Duplicação) ---

@app.post("/api/v1/users/register", response_model=UserResponse, tags=["Usuários"])
async def register_user(payload: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    # 1. Validar OTP
    valid = await verify_otp(db, payload.phone_e164, payload.otp_code)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de verificação inválido para o número informado."
        )

    # 2. Impedir contas duplicadas (Regra de Negócio: Cada número possui somente 1 conta)
    stmt = select(User).where(User.phone_e164 == payload.phone_e164)
    existing_user = (await db.execute(stmt)).scalars().first()
    pwd_hash = hashlib.sha256(payload.password.encode()).hexdigest()
    user_state = (payload.state or "").strip().upper()
    user_gender = (payload.gender or "").strip()

    if existing_user:
        if not existing_user.is_active:
            # Reativa se foi deletada previamente
            existing_user.is_active = True
            existing_user.is_paused = False
            existing_user.name = payload.name
            existing_user.bio = payload.bio or existing_user.bio
            existing_user.state = user_state or existing_user.state
            existing_user.gender = user_gender or existing_user.gender
            existing_user.password_hash = pwd_hash
            existing_user.consented_at = datetime.datetime.utcnow()
            await db.commit()
            await db.refresh(existing_user)
            return existing_user
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Este número de WhatsApp já possui uma conta ativa cadastrada."
            )

    now = datetime.datetime.utcnow()
    new_user = User(
        name=payload.name.strip(),
        phone_e164=payload.phone_e164,
        country_code=payload.country_code,
        bio=payload.bio or "Status do WhatsApp",
        state=user_state,
        gender=user_gender,
        password_hash=pwd_hash,
        consented_at=now,
        terms_accepted=True,
        is_active=True,
        is_paused=False,
        daily_quota=20,
        total_contacts_received=0,
        total_contacts_shared=0,
        reciprocity_score=1.0,
        created_at=now,
        updated_at=now
    )
    db.add(new_user)
    await db.flush()

    # Log de Auditoria LGPD
    audit = AuditLog(
        user_id=new_user.id,
        action="USER_REGISTERED_CONSENT_GIVEN",
        timestamp=now,
        details=f"Usuário {new_user.name} ({new_user.phone_e164}) UF={new_user.state} Sexo={new_user.gender} aceitou termos e autorizou compartilhamento."
    )
    db.add(audit)
    await db.commit()
    await db.refresh(new_user)

    return new_user

@app.get("/api/v1/users/{user_id}", response_model=UserResponse, tags=["Usuários"])
async def get_user_profile(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    return user

@app.get("/api/v1/users/{user_id}/stats", response_model=StatsResponse, tags=["Métricas & Estatísticas"])
async def get_user_stats(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    # Contatos adicionados à agenda
    added_stmt = select(func.count(ContactExchange.id)).where(
        ContactExchange.user_id == user_id,
        ContactExchange.added_to_device == True
    )
    added_count = (await db.execute(added_stmt)).scalar() or 0

    # Contatos recebidos hoje
    today_start = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_stmt = select(func.count(ContactExchange.id)).where(
        ContactExchange.user_id == user_id,
        ContactExchange.distributed_at >= today_start
    )
    today_received = (await db.execute(today_stmt)).scalar() or 0

    return StatsResponse(
        total_contacts_received=user.total_contacts_received,
        total_contacts_shared=user.total_contacts_shared,
        contacts_added_to_agenda=added_count,
        reciprocity_score=user.reciprocity_score,
        daily_quota_used=today_received,
        daily_quota_limit=user.daily_quota,
        is_paused=user.is_paused,
        is_active=user.is_active
    )

# --- Troca Recíproca de Contatos ---

@app.post("/api/v1/users/{user_id}/exchange", response_model=ExchangeBatchResponse, tags=["Troca de Contatos"])
async def request_exchange_batch(
    user_id: int,
    payload: ExchangeRequest,
    db: AsyncSession = Depends(get_db)
):
    try:
        contacts, remaining_quota, score, msg = await get_reciprocal_contacts_batch(
            db=db,
            user_id=user_id,
            batch_size=payload.batch_size
        )
        return ExchangeBatchResponse(
            contacts=contacts,
            count=len(contacts),
            remaining_quota=remaining_quota,
            reciprocity_score=score,
            message=msg
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/users/{user_id}/contacts", response_model=List[ContactDto], tags=["Troca de Contatos"])
async def get_received_contacts(
    user_id: int,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(ContactExchange, User)
        .join(User, ContactExchange.contact_user_id == User.id)
        .where(ContactExchange.user_id == user_id)
        .order_by(ContactExchange.distributed_at.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.all()

    return [
        ContactDto(
            id=exchange.id,
            user_id=contact_user.id,
            name=contact_user.name,
            phone_e164=contact_user.phone_e164,
            country_code=contact_user.country_code,
            bio=contact_user.bio or "Status do WhatsApp",
            distributed_at=exchange.distributed_at,
            added_to_device=exchange.added_to_device
        )
        for exchange, contact_user in rows
    ]

@app.post("/api/v1/users/{user_id}/contacts/mark-added", tags=["Troca de Contatos"])
async def mark_contacts_added(
    user_id: int,
    payload: MarkBatchAddedRequest,
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        update(ContactExchange)
        .where(
            ContactExchange.user_id == user_id,
            ContactExchange.contact_user_id.in_(payload.contact_user_ids)
        )
        .values(added_to_device=True)
    )
    await db.execute(stmt)
    await db.commit()
    return {"success": True, "message": "Contatos atualizados como salvos na agenda."}

# --- Privacidade & Exclusão de Conta (LGPD) ---

@app.post("/api/v1/users/{user_id}/privacy", tags=["Privacidade & LGPD"])
async def update_privacy(
    user_id: int,
    payload: PrivacyUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    user.is_paused = payload.is_paused
    audit = AuditLog(
        user_id=user.id,
        action="DISTRIBUTION_PAUSED" if payload.is_paused else "DISTRIBUTION_RESUMED",
        timestamp=datetime.datetime.utcnow(),
        details=f"Usuário {'pausou' if payload.is_paused else 'reativou'} a disponibilização do seu telefone na rede."
    )
    db.add(audit)
    await db.commit()
    return {
        "success": True,
        "is_paused": user.is_paused,
        "message": "Distribuição pausada com sucesso. Seu número não será entregue a novos participantes." if user.is_paused else "Distribuição reativada. Você voltará a participar da troca recíproca."
    }

@app.delete("/api/v1/users/{user_id}", tags=["Privacidade & LGPD"])
async def delete_user_account(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    # Conforme LGPD: Interrupção imediata da distribuição e inativação
    user.is_active = False
    user.is_paused = True
    user.name = "Conta Excluída (LGPD)"
    
    audit = AuditLog(
        user_id=user.id,
        action="ACCOUNT_DELETED_LGPD",
        timestamp=datetime.datetime.utcnow(),
        details=f"Exclusão definitiva solicitada pelo usuário. Distribuição de {user.phone_e164} revogada."
    )
    db.add(audit)
    await db.commit()
    return {
        "success": True,
        "message": "Conta e consentimento revogados com sucesso. Seu número foi permanentemente removido da rede de troca."
    }

# --- Denúncia e Moderação ---

@app.post("/api/v1/reports", tags=["Moderação"])
async def submit_report(payload: ReportRequest, db: AsyncSession = Depends(get_db)):
    report = Report(
        reporter_user_id=None,
        reported_user_id=payload.contact_user_id,
        reason=payload.reason,
        details=payload.details or "",
        status="pending",
        created_at=datetime.datetime.utcnow()
    )
    db.add(report)
    await db.commit()
    return {"success": True, "message": "Denúncia enviada com sucesso para análise da moderação."}

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

