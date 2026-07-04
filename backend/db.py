"""
Kryx DB - SQLAlchemy async models + session factory
Enterprise-grade schema for 0-day hunting platform
"""
import os
import secrets
from datetime import datetime
from sqlalchemy import String, Text, Float, Integer, DateTime, ForeignKey, JSON, Boolean, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from enum import Enum

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://kryx:kryx@localhost:5432/kryx",
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# Enums
class SubscriptionTier(str, Enum):
    STARTER = "starter"      # $99/mo
    PRO = "pro"              # $499/mo
    ENTERPRISE = "enterprise"  # $2999/mo
    APT = "apt"              # $9999/mo


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    MEMORY_CORRUPTION = "memory_corruption"
    INJECTION = "injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    RACE_CONDITION = "race_condition"
    LOGIC_FLAW = "logic_flaw"
    CRYPTO_WEAKNESS = "crypto_weakness"
    INFO_DISCLOSURE = "info_disclosure"
    OTHER = "other"


# ── Organizations (Multi-tenancy) ──

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    subscription_tier: Mapped[SubscriptionTier] = mapped_column(
        SQLEnum(SubscriptionTier), 
        default=SubscriptionTier.STARTER
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255))
    subscription_status: Mapped[str] = mapped_column(String(32), default="active")  # active|past_due|cancelled
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime)
    
    # Usage limits
    monthly_scan_limit: Mapped[int] = mapped_column(Integer, default=10)
    monthly_scans_used: Mapped[int] = mapped_column(Integer, default=0)
    
    # Integrations
    webhook_secret: Mapped[str | None] = mapped_column(String(128))
    slack_webhook_url: Mapped[str | None] = mapped_column(String(512))
    notification_webhooks: Mapped[list | None] = mapped_column(JSON)  # List of webhook URLs

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users: Mapped[list["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="organization")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="member")  # owner|admin|member|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="users")
    scans: Mapped[list["Scan"]] = relationship(back_populates="user")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="api_keys")

    @staticmethod
    def generate_key() -> str:
        return f"hx_{secrets.token_urlsafe(48)}"


# ── Scans & Targets ──

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    
    # Target info
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)  # web|repo|binary|source
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    
    # Status
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED)
    
    # Pipeline stages status
    static_analysis_done: Mapped[bool] = mapped_column(Boolean, default=False)
    fuzzing_done: Mapped[bool] = mapped_column(Boolean, default=False)
    variant_hunt_done: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_build_done: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_done: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Results
    summary: Mapped[str | None] = mapped_column(Text)
    report: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSON)
    
    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="scans")
    user: Mapped["User"] = relationship(back_populates="scans")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    attack_chains: Mapped[list["AttackChain"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


# ── Vulnerabilities ──

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Classification
    vuln_type: Mapped[VulnerabilityType] = mapped_column(SQLEnum(VulnerabilityType))
    severity: Mapped[VulnerabilitySeverity] = mapped_column(SQLEnum(VulnerabilitySeverity))
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    
    # Details
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(Text)  # file:line or URL
    
    # Evidence
    evidence: Mapped[dict | None] = mapped_column(JSON)  # tool outputs, crash dumps
    reproduction_steps: Mapped[list | None] = mapped_column(JSON)
    
    # Exploitation
    exploitability_score: Mapped[float | None] = mapped_column(Float)  # 0.0-1.0
    exploit_code: Mapped[str | None] = mapped_column(Text)
    exploit_technique: Mapped[str | None] = mapped_column(String(128))  # ROP|heap_spray|race|etc
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Impact
    impact_description: Mapped[str | None] = mapped_column(Text)
    
    # Remediation
    recommendation: Mapped[str | None] = mapped_column(Text)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_url: Mapped[str | None] = mapped_column(String(512))
    
    # Discovery method
    discovered_by_stage: Mapped[str | None] = mapped_column(String(32))  # static|fuzzing|variant|manual
    
    # Status
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    disclosed: Mapped[bool] = mapped_column(Boolean, default=False)
    disclosed_at: Mapped[datetime | None] = mapped_column(DateTime)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    organization: Mapped["Organization"] = relationship(back_populates="vulnerabilities")
    similar_vulns: Mapped[list["SimilarVulnerability"]] = relationship(
        foreign_keys="SimilarVulnerability.vuln_id",
        back_populates="vulnerability"
    )


class SimilarVulnerability(Base):
    """Tracks similar vulnerabilities found by variant hunter"""
    __tablename__ = "similar_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    similar_vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    similarity_score: Mapped[float] = mapped_column(Float)  # 0.0-1.0
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    vulnerability: Mapped["Vulnerability"] = relationship(
        foreign_keys=[vuln_id],
        back_populates="similar_vulns"
    )


# ── Attack Chains ──

class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    
    # Chain details
    vulnerability_ids: Mapped[list] = mapped_column(JSON)  # list of vuln IDs in order
    steps: Mapped[list] = mapped_column(JSON)  # detailed attack steps
    
    # Impact
    impact: Mapped[str] = mapped_column(Text)
    severity: Mapped[VulnerabilitySeverity] = mapped_column(SQLEnum(VulnerabilitySeverity))
    
    # Execution
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    success_rate: Mapped[float | None] = mapped_column(Float)  # 0.0-1.0
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="attack_chains")


# ── Exploit Templates & Knowledge Base ──

class ExploitTemplate(Base):
    __tablename__ = "exploit_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[VulnerabilityType] = mapped_column(SQLEnum(VulnerabilityType))
    technique: Mapped[str] = mapped_column(String(128))  # ROP|heap_spray|JIT_spray|etc
    
    # Template code
    code_template: Mapped[str] = mapped_column(Text)
    language: Mapped[str] = mapped_column(String(32))  # python|c|javascript|etc
    
    # Metadata
    description: Mapped[str | None] = mapped_column(Text)
    requirements: Mapped[list | None] = mapped_column(JSON)  # preconditions
    success_rate: Mapped[float | None] = mapped_column(Float)
    
    # Usage stats
    times_used: Mapped[int] = mapped_column(Integer, default=0)
    times_successful: Mapped[int] = mapped_column(Integer, default=0)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VulnerabilityPattern(Base):
    """Known vulnerability patterns for detection"""
    __tablename__ = "vulnerability_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    pattern_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[VulnerabilityType] = mapped_column(SQLEnum(VulnerabilityType))
    
    # Pattern matching
    code_signature: Mapped[str | None] = mapped_column(Text)  # regex or AST pattern
    ast_pattern: Mapped[dict | None] = mapped_column(JSON)
    
    # Examples
    examples: Mapped[list | None] = mapped_column(JSON)  # example code snippets
    cve_references: Mapped[list | None] = mapped_column(JSON)  # related CVEs
    
    # Detection metadata
    false_positive_rate: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[VulnerabilitySeverity] = mapped_column(SQLEnum(VulnerabilitySeverity))
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# Legacy compatibility (keep for migration)
class AuditResult(Base):
    __tablename__ = "audit_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="running")
    files_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[dict | None] = mapped_column(JSON)
    variants: Mapped[dict | None] = mapped_column(JSON)
    report: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)

    user: Mapped["User"] = relationship()


async def init_db():
    """Initialize database schema"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Dependency for getting async database session"""
    async with SessionLocal() as session:
        yield session


async def reset_monthly_usage():
    """Reset monthly scan usage counters (run via cron)"""
    async with SessionLocal() as session:
        from sqlalchemy import update
        await session.execute(
            update(Organization).values(monthly_scans_used=0)
        )
        await session.commit()
