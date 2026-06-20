# Database Schema v2.0

## Overview

Enterprise-grade multi-tenant architecture for Kryx 0-day hunting platform.

## Entity Relationship Diagram

```
Organizations (1) ──→ (N) Users
      │
      ├──→ (N) APIKeys
      ├──→ (N) Scans ──→ (N) Vulnerabilities
      │                      ├──→ (N) SimilarVulnerabilities
      │                      └──→ (N) AttackChains
      └──→ (N) Vulnerabilities (all org vulns)

ExploitTemplates (standalone reference data)
VulnerabilityPatterns (standalone reference data)
```

## Core Tables

### organizations
Multi-tenant organization management with subscription tiers.

**Key Fields:**
- `subscription_tier`: starter|pro|enterprise|apt
- `stripe_customer_id`: Stripe integration
- `monthly_scan_limit`: Usage cap per tier
- `monthly_scans_used`: Current period usage

**Subscription Tiers:**
- **Starter** ($99/mo): 10 scans, basic features
- **Pro** ($499/mo): 100 scans, exploit generation
- **Enterprise** ($2,999/mo): unlimited, private deployment
- **APT** ($9,999/mo): full 0-day hunting

### users
Organization members with role-based access.

**Roles:**
- `owner`: Full access, billing
- `admin`: Manage users, run scans
- `member`: Run scans, view results
- `viewer`: Read-only access

### api_keys
API authentication tokens for programmatic access.

**Key Format:** `hx_<48-char-token>`

### scans
Scan jobs through the 6-stage pipeline.

**Pipeline Stages (boolean flags):**
1. `static_analysis_done`
2. `fuzzing_done`
3. `variant_hunt_done`
4. `exploit_build_done`
5. `verification_done`

**Status Flow:**
```
queued → running → completed
                 ↘ failed
                 ↘ cancelled
```

### vulnerabilities
Discovered security vulnerabilities (first-class entities).

**Classification:**
- `vuln_type`: Enum of vulnerability categories
- `severity`: critical|high|medium|low|info
- `cve_id`: CVE identifier (if assigned)
- `cwe_id`: CWE weakness type

**Exploitation:**
- `exploitability_score`: 0.0-1.0 (how easy to exploit)
- `exploit_code`: Working PoC
- `exploit_technique`: ROP|heap_spray|race|etc
- `verified`: Tested in sandbox

**Discovery:**
- `discovered_by_stage`: Which harness stage found it
- `evidence`: Tool outputs, crash dumps (JSON)
- `reproduction_steps`: How to reproduce

**Lifecycle:**
- `is_false_positive`: Flagged by user/validator
- `disclosed`: Reported to vendor
- `disclosed_at`: Disclosure timestamp

### similar_vulnerabilities
Tracks variants found by variant hunter stage.

Links vulnerabilities with similarity scores (0.0-1.0).

### attack_chains
Multi-vulnerability exploit chains (APT-level attacks).

**Structure:**
- `vulnerability_ids`: Array of vuln IDs in order
- `steps`: Detailed attack sequence (JSON)
- `success_rate`: Measured reliability
- `verified`: Tested end-to-end

### exploit_templates
Reusable exploit code templates.

**Fields:**
- `code_template`: Template with placeholders
- `technique`: ROP|heap_spray|JIT_spray|etc
- `language`: python|c|javascript|etc
- `requirements`: Preconditions (JSON)
- `success_rate`: Historical success rate

**Usage Tracking:**
- `times_used`: How often template was used
- `times_successful`: Success count

### vulnerability_patterns
Known vulnerability patterns for static analysis.

**Pattern Types:**
- `code_signature`: Regex pattern
- `ast_pattern`: AST structure (JSON)
- `examples`: Code snippets
- `cve_references`: Related CVEs

## Enums

### SubscriptionTier
- `starter`, `pro`, `enterprise`, `apt`

### ScanStatus
- `queued`, `running`, `completed`, `failed`, `cancelled`

### VulnerabilitySeverity
- `critical`, `high`, `medium`, `low`, `info`

### VulnerabilityType
- `memory_corruption` (buffer overflow, UAF, double-free)
- `injection` (SQLi, command injection, XXE)
- `xss`, `csrf`
- `auth_bypass`, `idor`
- `race_condition`
- `logic_flaw`
- `crypto_weakness`
- `info_disclosure`
- `other`

## Indexes

Performance indexes on high-traffic queries:

```sql
-- Vulnerabilities
idx_vulns_severity ON vulnerabilities(severity)
idx_vulns_type ON vulnerabilities(vuln_type)
idx_vulns_verified ON vulnerabilities(verified)

-- Scans
idx_scans_status ON scans(status)
idx_scans_created ON scans(created_at DESC)

-- Built-in indexes
users.email (unique)
api_keys.key (unique)
organizations.stripe_customer_id (unique)
```

## Usage Examples

### Create Organization with Subscription

```python
org = Organization(
    name="Acme Corp",
    subscription_tier=SubscriptionTier.PRO,
    monthly_scan_limit=100,
    stripe_customer_id="cus_..."
)
await session.add(org)
await session.commit()
```

### Generate API Key

```python
api_key = APIKey(
    organization_id=org.id,
    key=APIKey.generate_key(),  # hx_xxxxx
    name="CI/CD Pipeline"
)
await session.add(api_key)
await session.commit()
```

### Create Scan

```python
scan = Scan(
    organization_id=org.id,
    user_id=user.id,
    target_type="repo",
    target="https://github.com/user/repo",
    status=ScanStatus.QUEUED
)
await session.add(scan)
await session.commit()
```

### Record Vulnerability

```python
vuln = Vulnerability(
    scan_id=scan.id,
    organization_id=org.id,
    vuln_type=VulnerabilityType.MEMORY_CORRUPTION,
    severity=VulnerabilitySeverity.CRITICAL,
    name="Buffer overflow in parse_header()",
    description="...",
    location="src/parser.c:142",
    exploitability_score=0.85,
    exploit_code="# ROP exploit...",
    exploit_technique="ROP",
    discovered_by_stage="static"
)
await session.add(vuln)
await session.commit()
```

### Link Similar Vulnerabilities

```python
similar = SimilarVulnerability(
    vuln_id=vuln1.id,
    similar_vuln_id=vuln2.id,
    similarity_score=0.92
)
await session.add(similar)
await session.commit()
```

### Create Attack Chain

```python
chain = AttackChain(
    scan_id=scan.id,
    name="Auth bypass → SQLi → RCE",
    description="...",
    vulnerability_ids=[vuln1.id, vuln2.id, vuln3.id],
    steps=[
        {"step": 1, "action": "Bypass auth via IDOR"},
        {"step": 2, "action": "SQLi in admin panel"},
        {"step": 3, "action": "Upload webshell via SQLi"}
    ],
    impact="Full server compromise",
    severity=VulnerabilitySeverity.CRITICAL,
    verified=True
)
await session.add(chain)
await session.commit()
```

## Migration

### From v1 to v2

```bash
cd backend
python migrate_to_v2.py
```

This will:
1. Create new tables
2. Migrate existing users to default organization
3. Update scan statuses
4. Create indexes
5. Seed exploit templates

### Rollback

```bash
python migrate_to_v2.py rollback
```

**⚠️ Warning:** This drops new tables and loses data.

## Maintenance

### Reset Monthly Usage (Cron Job)

```bash
# Run on 1st of each month
0 0 1 * * cd /app/backend && python -c "from db import reset_monthly_usage; import asyncio; asyncio.run(reset_monthly_usage())"
```

### Backup

```bash
# PostgreSQL dump
pg_dump -h localhost -U kryx -d kryx > backup_$(date +%Y%m%d).sql

# Restore
psql -h localhost -U kryx -d kryx < backup_20260607.sql
```

## Performance Tuning

### Recommended PostgreSQL Settings

```sql
-- For high-traffic production
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET min_wal_size = '1GB';
ALTER SYSTEM SET max_wal_size = '4GB';
```

### Connection Pooling

Use PgBouncer or SQLAlchemy's connection pool:

```python
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,           # Max connections
    max_overflow=10,        # Burst capacity
    pool_timeout=30,        # Wait time
    pool_recycle=3600       # Recycle after 1hr
)
```

## Security

### Sensitive Data

- Passwords: bcrypt hashed, never stored plain
- API keys: 48-byte secure random tokens
- Stripe IDs: encrypted at rest (if using column encryption)

### Access Control

All queries should filter by `organization_id`:

```python
# ✅ Good
vulns = await session.execute(
    select(Vulnerability)
    .where(Vulnerability.organization_id == org_id)
)

# ❌ Bad - potential data leak
vulns = await session.execute(select(Vulnerability))
```

### Rate Limiting

Check `monthly_scans_used` before creating scans:

```python
if org.monthly_scans_used >= org.monthly_scan_limit:
    raise HTTPException(403, "Monthly scan limit reached")
```

## Future Enhancements

- [ ] Audit log table (all changes tracked)
- [ ] Webhook delivery log
- [ ] Team permissions (granular RBAC)
- [ ] Custom fields per organization
- [ ] Data retention policies
- [ ] Archival to S3 for old scans

---

**Version:** 2.0  
**Last Updated:** 2026-06-07
