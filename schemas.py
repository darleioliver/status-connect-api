import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

class OtpRequest(BaseModel):
    phone_e164: str = Field(..., description="Telefone com código do país (ex: +5511999998888)")

    @field_validator("phone_e164")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        clean = v.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if not clean.startswith("+"):
            clean = "+" + clean
        if len(clean) < 10 or len(clean) > 20:
            raise ValueError("Número de telefone inválido.")
        return clean

class OtpVerifyRequest(BaseModel):
    phone_e164: str
    code: str = Field(..., min_length=4, max_length=8)

class LoginRequest(BaseModel):
    phone_e164: str = Field(..., description="Telefone com código do país (ex: +5511999998888)")
    password: str = Field(..., min_length=4, max_length=128, description="Senha de acesso")

    @field_validator("phone_e164")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        clean = v.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if not clean.startswith("+"):
            clean = "+" + clean
        if len(clean) < 10 or len(clean) > 20:
            raise ValueError("Número de telefone inválido.")
        return clean

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    phone_e164: str
    country_code: str = Field(default="+55", max_length=10)
    bio: Optional[str] = Field(default="Status do WhatsApp", max_length=200)
    state: Optional[str] = Field(default="", max_length=10, description="Estado/UF do usuário")
    gender: Optional[str] = Field(default="", max_length=30, description="Sexo do usuário")
    password: str = Field(..., min_length=4, max_length=128, description="Senha de acesso do usuário")
    accept_terms: bool = Field(..., description="Aceite dos termos de uso")
    accept_sharing_consent: bool = Field(..., description="Consentimento voluntário de compartilhamento LGPD")
    otp_code: str = Field(..., description="Código de confirmação de posse do número")

    @field_validator("accept_terms", "accept_sharing_consent")
    @classmethod
    def validate_consents(cls, v: bool) -> bool:
        if not v:
            raise ValueError("É obrigatório aceitar os termos e dar consentimento para participar da rede.")
        return v

class UserResponse(BaseModel):
    id: int
    name: str
    phone_e164: str
    country_code: str
    bio: Optional[str]
    state: Optional[str] = ""
    gender: Optional[str] = ""
    is_active: bool
    is_paused: bool
    total_contacts_received: int
    total_contacts_shared: int
    reciprocity_score: float
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class ContactDto(BaseModel):
    id: int
    user_id: int
    name: str
    phone_e164: str
    country_code: str
    bio: Optional[str] = ""
    distributed_at: datetime.datetime
    added_to_device: bool

class ExchangeRequest(BaseModel):
    batch_size: int = Field(default=10, ge=1, le=50)

class ExchangeBatchResponse(BaseModel):
    contacts: List[ContactDto]
    count: int
    remaining_quota: int
    reciprocity_score: float
    message: str

class StatsResponse(BaseModel):
    total_contacts_received: int
    total_contacts_shared: int
    contacts_added_to_agenda: int
    reciprocity_score: float
    daily_quota_used: int
    daily_quota_limit: int
    is_paused: bool
    is_active: bool

class PrivacyUpdateRequest(BaseModel):
    is_paused: bool

class ReportRequest(BaseModel):
    contact_user_id: int
    reason: str
    details: Optional[str] = ""

class MarkBatchAddedRequest(BaseModel):
    contact_user_ids: List[int]

class AdminUserDto(BaseModel):
    id: int
    name: str
    phone_e164: str
    country_code: str
    is_active: bool
    is_paused: bool
    total_contacts_received: int
    total_contacts_shared: int
    reciprocity_score: float
    created_at: datetime.datetime
