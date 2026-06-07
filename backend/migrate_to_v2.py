"""
Database Migration: v1 → v2 (Enterprise Schema)

Migrates from simple user/scan schema to full enterprise architecture with:
- Organizations & multi-tenancy
- Subscription tiers & billing
- API keys
- Vulnerabilities as first-class entities
- Attack chains
- Exploit templates & knowledge base

Run: python migrate_to_v2.py
"""
import asyncio
from sqlalchemy import text
from backend.db import engine, Base, SubscriptionTier


async def migrate():
    print("🚀 Starting migration to v2 schema...")
    
    async with engine.begin() as conn:
        print("📋 Step 1: Creating new tables...")
        await conn.run_sync(Base.metadata.create_all)
        print("✅ New tables created")
        
        print("\n📋 Step 2: Migrating existing users to organizations...")
        
        # Check if old users exist
        result = await conn.execute(text("SELECT COUNT(*) FROM users WHERE organization_id IS NULL"))
        orphaned_users = result.scalar()
        
        if orphaned_users > 0:
            # Create default organization for existing users
            await conn.execute(text("""
                INSERT INTO organizations (name, subscription_tier, monthly_scan_limit, created_at)
                VALUES ('Legacy Organization', 'pro', 100, NOW())
                ON CONFLICT DO NOTHING
            """))
            
            # Get the default org ID
            result = await conn.execute(text("SELECT id FROM organizations WHERE name = 'Legacy Organization' LIMIT 1"))
            org_id = result.scalar()
            
            # Assign all users without org to default org
            await conn.execute(text(f"""
                UPDATE users 
                SET organization_id = {org_id}, role = 'owner'
                WHERE organization_id IS NULL
            """))
            
            print(f"✅ Migrated {orphaned_users} users to default organization")
        
        print("\n📋 Step 3: Migrating scans to new structure...")
        
        # Add organization_id to scans based on user's org
        await conn.execute(text("""
            UPDATE scans 
            SET organization_id = (SELECT organization_id FROM users WHERE users.id = scans.user_id)
            WHERE organization_id IS NULL
        """))
        
        # Set default values for new fields
        await conn.execute(text("""
            UPDATE scans 
            SET 
                target_type = 'web',
                status = CASE 
                    WHEN status = 'running' THEN 'running'
                    WHEN status = 'done' THEN 'completed'
                    ELSE 'failed'
                END
            WHERE target_type IS NULL
        """))
        
        print("✅ Scans migrated")
        
        print("\n📋 Step 4: Creating indexes for performance...")
        
        # Add useful indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_verified ON vulnerabilities(verified)",
            "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)",
        ]
        
        for idx_sql in indexes:
            await conn.execute(text(idx_sql))
        
        print("✅ Indexes created")
        
        print("\n📋 Step 5: Seeding exploit templates...")
        
        # Add some basic exploit templates
        templates = [
            ("Stack Buffer Overflow ROP", "memory_corruption", "ROP", "python"),
            ("Heap Spray (JavaScript)", "memory_corruption", "heap_spray", "javascript"),
            ("SQL Injection Exploit", "injection", "sqli", "python"),
            ("XSS Cookie Stealer", "xss", "xss_steal", "javascript"),
        ]
        
        for name, vtype, tech, lang in templates:
            await conn.execute(text(f"""
                INSERT INTO exploit_templates (name, vuln_type, technique, language, code_template, created_at)
                VALUES ('{name}', '{vtype}', '{tech}', '{lang}', '# Template placeholder', NOW())
                ON CONFLICT DO NOTHING
            """))
        
        print("✅ Exploit templates seeded")
    
    print("\n🎉 Migration completed successfully!")
    print("\n📊 Next steps:")
    print("  1. Review organizations table")
    print("  2. Set up Stripe integration")
    print("  3. Generate API keys for organizations")
    print("  4. Test new vulnerability tracking")


async def rollback():
    """Rollback migration (careful!)"""
    print("⚠️  Rolling back migration...")
    
    async with engine.begin() as conn:
        # Drop new tables
        new_tables = [
            "similar_vulnerabilities",
            "attack_chains",
            "vulnerabilities",
            "exploit_templates",
            "vulnerability_patterns",
            "api_keys",
        ]
        
        for table in new_tables:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
        
        print("✅ Rollback completed")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())
