import datetime
import re
import unicodedata
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

_EXACT_OFFENSIVE_TOKENS = {
    "cu", "cuz", "cuzao", "cuzona", "cuzinho",
    "fdp", "vsf", "tnc", "vtnc", "pqp", "kct", "bct", "krl",
    "puta", "puto", "putas", "putos",
    "pica", "pika", "rola", "roula", "pau",
    "foda", "fodas", "fode", "fude",
    "vaca", "burro", "burra", "anta", "jumento", "jumenta",
    "bicha", "bixa", "viado", "viada", "viadao", "viadinho", "bichona",
    "corno", "corna", "cornudo", "chifrudo",
    "bosta", "merda", "merdas", "cagao", "cagona",
    "babaca", "babacas", "otario", "otaria", "otarios", "otarias",
    "idiota", "idiotas", "imbecil", "imbecis",
    "escroto", "escrota", "escrotao",
    "trouxa", "trouxo", "lixo",
    "piranha", "piranhas", "vagabundo", "vagabunda", "vagabundos", "vagabundas",
    "vadia", "vadio", "vadias",
    "retardado", "retardada", "retardados", "retardadas",
    "safado", "safada", "safados", "safadas",
    "pelado", "pelada", "pelados", "peladas",
    "tesao", "tesuda", "tesudo",
    "sexo", "sex", "porn", "porno", "xxx", "nude", "nudes", "anal",
    "fuck", "shit", "bitch", "dick", "cock", "pussy", "whore", "slut", "asshole", "cum",
    "porra", "porr4",
}

_UNAMBIGUOUS_OFFENSIVE_STEMS = (
    "caralho", "kralho", "karalho", "karaleo", "caraleo",
    "porra", "porr4",
    "buceta", "boceta", "buseta", "boseta",
    "xoxota", "xereca", "chereca", "piroca", "piroka",
    "arrombado", "arrombada", "arrombados", "arrombadas",
    "filhodaputa", "filhadaputa", "filhosdaputa",
    "paunocu", "vaitomarnocu", "tomarnocu", "vaisefuder", "vaisefoder",
    "fuder", "foder", "fudido", "fudida", "fodido", "fodida", "fodase",
    "punheta", "punheteiro", "siririca", "boquete", "chuparola", "chupapau",
    "prostituta", "prostituto", "prostituicao", "putaria", "putinha", "putinho",
    "desgraca", "desgracado", "desgracada",
    "sapatao", "sapatona",
    "pornogr", "onlyfans", "xvideos", "pornhub",
    "estupr", "pedofil", "nazist",
    "motherfucker", "nigger", "faggot",
)

_COLLAPSED_EXACT_TOKENS = {re.sub(r"(.)\1+", r"\1", t) for t in _EXACT_OFFENSIVE_TOKENS}
_COLLAPSED_UNAMBIGUOUS_STEMS = tuple({re.sub(r"(.)\1+", r"\1", s) for s in _UNAMBIGUOUS_OFFENSIVE_STEMS if len(s) >= 6})

_OFFENSIVE_PHRASES = (
    "filho da puta", "filha da puta", "pau no cu",
    "vai tomar no cu", "tomar no cu", "vai se fuder", "vai se foder",
    "vai pro inferno", "chupa rola", "chupa pau", "vai se ferrar",
)


def _contains_offensive_content(text: str) -> bool:
    if not text or not text.strip():
        return False
    decomposed = unicodedata.normalize("NFD", text)
    base = "".join(c for c in decomposed if unicodedata.category(c) != "Mn").lower()
    leet_map = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
    variants = (base, base.translate(leet_map))
    for variant in variants:
        spaced = re.sub(r"[^a-z0-9]+", " ", variant).strip()
        if not spaced:
            continue
        single_spaced = re.sub(r"\s+", " ", spaced)
        if any(p in single_spaced for p in _OFFENSIVE_PHRASES):
            return True
        for word in single_spaced.split(" "):
            if word in _EXACT_OFFENSIVE_TOKENS:
                return True
            c2 = re.sub(r"(.)\1{2,}", r"\1\1", word)
            c1 = re.sub(r"(.)\1+", r"\1", word)
            if c2 in _EXACT_OFFENSIVE_TOKENS or c1 in _COLLAPSED_EXACT_TOKENS:
                return True
            if any(s in word or s in c2 for s in _UNAMBIGUOUS_OFFENSIVE_STEMS) or any(s in c1 for s in _COLLAPSED_UNAMBIGUOUS_STEMS):
                return True
        compact = spaced.replace(" ", "")
        compact_c2 = re.sub(r"(.)\1{2,}", r"\1\1", compact)
        compact_c1 = re.sub(r"(.)\1+", r"\1", compact)
        if any(s in compact or s in compact_c2 for s in _UNAMBIGUOUS_OFFENSIVE_STEMS) or any(s in compact_c1 for s in _COLLAPSED_UNAMBIGUOUS_STEMS):
            return True
        for raw_token in variant.strip().split():
            cleaned = re.sub(r"[^a-z0-9]+", "", raw_token)
            if cleaned in _EXACT_OFFENSIVE_TOKENS or re.sub(r"(.)\1+", r"\1", cleaned) in _COLLAPSED_EXACT_TOKENS:
                return True
    return False

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
    otp_code: str = Field(default="123456", description="Código de confirmação opcional")

    @field_validator("name")
    @classmethod
    def validate_name_clean(cls, v: str) -> str:
        if _contains_offensive_content(v):
            raise ValueError("O nome ou sobrenome contém palavras ofensivas e não é permitido.")
        return v

    @field_validator("bio")
    @classmethod
    def validate_bio_clean(cls, v: Optional[str]) -> Optional[str]:
        if v and _contains_offensive_content(v):
            raise ValueError("A bio/descrição contém palavras ofensivas e não é permitida.")
        return v

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
    is_premium: bool = False
    total_contacts_received: int
    total_contacts_shared: int
    reciprocity_score: float
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class ContactDto(BaseModel):
    id: int = 0
    user_id: int
    name: str
    phone_e164: str
    country_code: str
    bio: Optional[str] = ""
    state: Optional[str] = ""
    gender: Optional[str] = ""
    is_premium: bool = False
    distributed_at: Optional[datetime.datetime] = None
    added_to_device: bool = False

class ExchangeRequest(BaseModel):
    batch_size: int = Field(default=10, ge=1, le=100)

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
    is_premium: bool = False

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
    state: Optional[str] = ""
    gender: Optional[str] = ""
    is_active: bool
    is_paused: bool
    is_premium: bool = False
    total_received: int
    total_shared: int
    reciprocity_score: float
    created_at: datetime.datetime

class DeviceTokenRegisterRequest(BaseModel):
    fcm_token: str = Field(..., min_length=20, max_length=512)
    user_id: Optional[int] = None
    device_platform: str = Field(default="android", max_length=20)

class PushSendRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=120)
    body: str = Field(..., min_length=1, max_length=500)
    audience: str = Field(default="all") # all, free, premium, paused, test
    target_user_id: Optional[int] = None
    action_label: Optional[str] = Field(default=None, max_length=60)
    action_url: Optional[str] = Field(default=None, max_length=500)

