"""
Hexor Webhooks & Integrations

External integrations for:
- GitHub (webhooks, security advisories)
- GitLab (CI/CD pipelines)
- Jenkins (build triggers)
- Generic webhooks

Enables:
- Automated scanning on code push
- PR/MR security checks
- Build pipeline integration
- Real-time notifications
"""
import hashlib
import hmac
import json
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db import Organization, Scan, ScanStatus
from core.harness.supervisor_v2 import run_pipeline


class WebhookService:
    """Handle incoming webhooks from external services"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def handle_github_webhook(
        self,
        payload: Dict[str, Any],
        signature: str,
        org_id: int
    ) -> Dict[str, Any]:
        """
        Handle GitHub webhook events.
        
        Supported events:
        - push: Scan repository on code push
        - pull_request: Scan PR for vulnerabilities
        - release: Scan new release
        """
        event_type = payload.get("hook", {}).get("type") or "push"
        
        # Verify signature (if secret configured)
        org = await self.db.get(Organization, org_id)
        if org and org.webhook_secret:
            if not self._verify_github_signature(payload, signature, org.webhook_secret):
                raise ValueError("Invalid webhook signature")
        
        result = {"event": event_type, "status": "processed"}
        
        # Handle different event types
        if "ref" in payload:  # Push event
            result = await self._handle_github_push(payload, org_id)
        
        elif "pull_request" in payload:
            result = await self._handle_github_pr(payload, org_id)
        
        elif "release" in payload:
            result = await self._handle_github_release(payload, org_id)
        
        return result
    
    async def _handle_github_push(
        self,
        payload: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """Handle GitHub push event - trigger scan"""
        repo = payload.get("repository", {})
        repo_url = repo.get("clone_url")
        branch = payload.get("ref", "").replace("refs/heads/", "")
        
        if not repo_url:
            return {"status": "error", "message": "No repository URL"}
        
        # Create scan
        scan = Scan(
            organization_id=org_id,
            target_type="repo",
            target=f"{repo_url} (branch: {branch})",
            status=ScanStatus.QUEUED
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        
        # Run scan in background
        asyncio.create_task(
            run_pipeline(repo_url, "repo", scan.id, self.db)
        )
        
        return {
            "status": "scan_triggered",
            "scan_id": scan.id,
            "repository": repo.get("full_name"),
            "branch": branch
        }
    
    async def _handle_github_pr(
        self,
        payload: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """Handle GitHub PR event - scan PR diff"""
        action = payload.get("action")
        pr = payload.get("pull_request", {})
        
        # Only scan on open/synchronize
        if action not in ["opened", "synchronize"]:
            return {"status": "skipped", "reason": f"Action {action} ignored"}
        
        repo = payload.get("repository", {})
        pr_url = pr.get("url") or repo.get("clone_url")
        pr_number = pr.get("number")
        
        # Create scan
        scan = Scan(
            organization_id=org_id,
            target_type="repo",
            target=f"{repo.get('full_name')} (PR #{pr_number})",
            status=ScanStatus.QUEUED
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        
        # Run scan
        asyncio.create_task(
            run_pipeline(pr_url, "repo", scan.id, self.db)
        )
        
        return {
            "status": "scan_triggered",
            "scan_id": scan.id,
            "pr": pr_number,
            "action": action
        }
    
    async def _handle_github_release(
        self,
        payload: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """Handle GitHub release - scan new release"""
        release = payload.get("release", {})
        repo = payload.get("repository", {})
        
        if release.get("draft") or release.get("prerelease"):
            return {"status": "skipped", "reason": "Draft/prerelease"}
        
        # Create scan
        scan = Scan(
            organization_id=org_id,
            target_type="repo",
            target=f"{repo.get('full_name')} (release: {release.get('tag_name')})",
            status=ScanStatus.QUEUED
        )
        self.db.add(scan)
        await self.db.commit()
        
        return {
            "status": "scan_triggered",
            "scan_id": scan.id,
            "release": release.get("tag_name")
        }
    
    def _verify_github_signature(
        self,
        payload: Dict[str, Any],
        signature: str,
        secret: str
    ) -> bool:
        """Verify GitHub webhook signature"""
        expected = "sha256=" + hmac.new(
            secret.encode(),
            json.dumps(payload).encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected)
    
    async def handle_gitlab_webhook(
        self,
        payload: Dict[str, Any],
        token: str,
        org_id: int
    ) -> Dict[str, Any]:
        """
        Handle GitLab webhook events.
        
        Supported events:
        - Push Hook
        - Merge Request Hook
        - Tag Push Hook
        """
        event_name = payload.get("object_kind", "push")
        
        # Verify token
        org = await self.db.get(Organization, org_id)
        if org and org.webhook_secret:
            if token != org.webhook_secret:
                raise ValueError("Invalid webhook token")
        
        result = {"event": event_name, "status": "processed"}
        
        if event_name == "push":
            result = await self._handle_gitlab_push(payload, org_id)
        
        elif event_name == "merge_request":
            result = await self._handle_gitlab_mr(payload, org_id)
        
        return result
    
    async def _handle_gitlab_push(
        self,
        payload: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """Handle GitLab push event"""
        project = payload.get("project", {})
        repo_url = project.get("git_http_url")
        branch = payload.get("ref", "").replace("refs/heads/", "")
        
        scan = Scan(
            organization_id=org_id,
            target_type="repo",
            target=f"{project.get('path_with_namespace')} (branch: {branch})",
            status=ScanStatus.QUEUED
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        
        asyncio.create_task(
            run_pipeline(repo_url, "repo", scan.id, self.db)
        )
        
        return {
            "status": "scan_triggered",
            "scan_id": scan.id
        }
    
    async def _handle_gitlab_mr(
        self,
        payload: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """Handle GitLab merge request"""
        mr = payload.get("object_attributes", {})
        action = mr.get("action")
        
        if action not in ["open", "update"]:
            return {"status": "skipped", "reason": f"Action {action}"}
        
        project = payload.get("project", {})
        
        scan = Scan(
            organization_id=org_id,
            target_type="repo",
            target=f"{project.get('path_with_namespace')} (MR !{mr.get('iid')})",
            status=ScanStatus.QUEUED
        )
        self.db.add(scan)
        await self.db.commit()
        
        return {
            "status": "scan_triggered",
            "scan_id": scan.id
        }


class NotificationService:
    """Send notifications to external services"""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=10.0)
    
    async def send_webhook(
        self,
        url: str,
        event: str,
        data: Dict[str, Any],
        secret: Optional[str] = None
    ) -> bool:
        """
        Send webhook notification.
        
        Args:
            url: Webhook URL
            event: Event type (scan.completed, vuln.found, etc)
            data: Event payload
            secret: Optional secret for signing
        
        Returns:
            True if delivered successfully
        """
        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        headers = {"Content-Type": "application/json"}
        
        # Sign payload if secret provided
        if secret:
            signature = hmac.new(
                secret.encode(),
                json.dumps(payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-Hexor-Signature"] = f"sha256={signature}"
        
        try:
            response = await self.http_client.post(
                url,
                json=payload,
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[Webhook] Failed to send to {url}: {e}")
            return False
    
    async def send_slack_notification(
        self,
        webhook_url: str,
        message: str,
        severity: str = "info"
    ) -> bool:
        """Send Slack notification via webhook"""
        color_map = {
            "critical": "#FF0000",
            "high": "#FFA500",
            "medium": "#FFFF00",
            "low": "#00FF00",
            "info": "#0000FF"
        }
        
        payload = {
            "attachments": [{
                "color": color_map.get(severity, "#808080"),
                "text": message,
                "footer": "Hexor Security Platform"
            }]
        }
        
        try:
            response = await self.http_client.post(webhook_url, json=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"[Slack] Failed: {e}")
            return False
    
    async def notify_scan_complete(
        self,
        scan: Scan,
        webhook_urls: list[str]
    ) -> None:
        """Notify about completed scan"""
        for url in webhook_urls:
            await self.send_webhook(
                url,
                "scan.completed",
                {
                    "scan_id": scan.id,
                    "target": scan.target,
                    "status": scan.status,
                    "summary": scan.summary,
                    "vulns_found": scan.stats.get("total_findings", 0) if scan.stats else 0
                }
            )
