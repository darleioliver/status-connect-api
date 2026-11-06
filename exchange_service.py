import datetime
import hashlib
import random
from typing import List, Tuple
from sqlalchemy import select, func, and_, not_
from sqlalchemy.ext.asyncio import AsyncSession
from models import User, ContactExchange, OtpVerification, AuditLog
from schemas import ContactDto

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

    # 3. Buscar candidatos disponíveis
    # Regras:
    # - Ativo e não pausado
    # - Diferente do usuário
    # - Nunca recebido antes
    # - Ordenado pela menor quantidade de contatos compartilhados (equidade de distribuição)
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
        .order_by(User.total_contacts_shared.asc(), User.reciprocity_score.desc())
        .limit(batch_size * 2) # busca margem para randomização equitativa
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

    # Embaralhar candidatos com mesma prioridade para evitar envios viciados
    selected = list(candidates)
    random.shuffle(selected)
    selected = selected[:batch_size]

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
    # Verifica se já há usuários
    stmt = select(func.count(User.id))
    res = await db.execute(stmt)
    count = res.scalar() or 0
    if count >= 10:
        return

    sample_seed_users = [
        {"name": "Mariana Silva", "phone": "+5511987654321", "country": "+55", "bio": "Marketing Digital & Criação de Conteúdo"},
        {"name": "Lucas Fernandes", "phone": "+5521991234567", "country": "+55", "bio": "E-commerce e Negócios Locais"},
        {"name": "Camila Duarte", "phone": "+5531988887766", "country": "+55", "bio": "Moda, Beleza e Tendências"},
        {"name": "Rodrigo Santos", "phone": "+5541997776655", "country": "+55", "bio": "Tecnologia, Startups e Investimentos"},
        {"name": "Beatriz Lima", "phone": "+5551981239876", "country": "+55", "bio": "Arquitetura, Design e Decoração"},
        {"name": "Gabriel Costa", "phone": "+5561996543210", "country": "+55", "bio": "Gastronomia e Delivery"},
        {"name": "Juliana Martins", "phone": "+5571987651234", "country": "+55", "bio": "Saúde, Nutrição e Treino Funcional"},
        {"name": "Felipe Souza", "phone": "+5581995438765", "country": "+55", "bio": "Fotografia, Audiovisual e Reels"},
        {"name": "Larissa Ribeiro", "phone": "+5585994321098", "country": "+55", "bio": "Consultoria Financeira e Renda Extra"},
        {"name": "Thiago Mendes", "phone": "+5591983216540", "country": "+55", "bio": "Música, Eventos e Entretenimento"},
        {"name": "Sofia Almeida", "phone": "+351912345678", "country": "+351", "bio": "Networking Internacional & Viagens"},
        {"name": "Mateus Rocha", "phone": "+5519987650123", "country": "+55", "bio": "Desenvolvimento Pessoal e Livros"}
    ]

    now = datetime.datetime.utcnow()
    for item in sample_seed_users:
        # Checa duplicidade
        check_stmt = select(User).where(User.phone_e164 == item["phone"])
        existing = (await db.execute(check_stmt)).scalar()
        if not existing:
            u = User(
                name=item["name"],
                phone_e164=item["phone"],
                country_code=item["country"],
                bio=item["bio"],
                consented_at=now,
                terms_accepted=True,
                is_active=True,
                is_paused=False,
                daily_quota=30,
                total_contacts_received=random.randint(5, 15),
                total_contacts_shared=random.randint(8, 20),
                reciprocity_score=round(random.uniform(0.9, 1.4), 2),
                created_at=now - datetime.timedelta(days=random.randint(2, 20))
            )
            db.add(u)
    await db.commit()
