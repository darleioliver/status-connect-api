import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    phone_e164 = Column(String(32), unique=True, index=True, nullable=False)
    country_code = Column(String(10), default="+55", nullable=False)
    bio = Column(String(200), default="", nullable=True) # Ex: nicho ou interesse (Empreendedorismo, etc)
    state = Column(String(10), default="", nullable=True) # UF (ex: SP, RJ, MG)
    gender = Column(String(30), default="", nullable=True) # Feminino, Masculino, etc
    password_hash = Column(String(255), default="", nullable=True) # Senha criptografada do usuário
    consented_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    terms_accepted = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, index=True, nullable=False)
    is_paused = Column(Boolean, default=False, index=True, nullable=False)
    is_premium = Column(Boolean, default=False, index=True, nullable=False)
    last_active_date = Column(String(16), default="", nullable=True) # Data YYYY-MM-DD (Brasilia) da ultima ativacao
    daily_quota = Column(Integer, default=20, nullable=False)
    total_contacts_received = Column(Integer, default=0, nullable=False)
    total_contacts_shared = Column(Integer, default=0, nullable=False)
    reciprocity_score = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    # Relacionamentos
    received_exchanges = relationship(
        "ContactExchange",
        foreign_keys="ContactExchange.user_id",
        back_populates="recipient_user",
        cascade="all, delete-orphan"
    )
    given_exchanges = relationship(
        "ContactExchange",
        foreign_keys="ContactExchange.contact_user_id",
        back_populates="shared_contact_user",
        cascade="all, delete-orphan"
    )

class ContactExchange(Base):
    __tablename__ = "contact_exchanges"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    contact_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    distributed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    added_to_device = Column(Boolean, default=False, nullable=False)
    is_blocked = Column(Boolean, default=False, nullable=False)

    # Restrição única para garantir deduplicação estrita: o usuário nunca recebe o mesmo contato 2 vezes!
    __table_args__ = (
        UniqueConstraint("user_id", "contact_user_id", name="uq_user_contact_exchange"),
        Index("idx_user_distributed", "user_id", "distributed_at"),
    )

    recipient_user = relationship("User", foreign_keys=[user_id], back_populates="received_exchanges")
    shared_contact_user = relationship("User", foreign_keys=[contact_user_id], back_populates="given_exchanges")

class OtpVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    phone_e164 = Column(String(32), index=True, nullable=False)
    code_hash = Column(String(128), nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    reporter_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reported_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    reason = Column(String(100), nullable=False)
    details = Column(Text, default="", nullable=True)
    status = Column(String(20), default="pending", nullable=False) # pending, resolved, dismissed
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    details = Column(String(500), default="", nullable=True)
