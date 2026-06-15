# Webhooks & Integrations

## Overview

Kryx integrates with external services via webhooks for automated security scanning.

## Supported Platforms

### GitHub

**Webhook URL:** `POST /api/webhooks/github/{org_id}`

**Events:**
- **Push** — Triggers scan on push to any branch
- **Pull Request** — Scans PR on open/synchronize
- **Release** — Scans on new release publish

**Setup:**
1. Go to repo Settings → Webhooks → Add webhook
2. Payload URL: `https://your-kryx.com/api/webhooks/github/1`
3. Content type: `application/json`
4. Secret: (optional) set in org settings
5. Events: Push, Pull request, Release

**Example Payload:**
```json
{
  "status": "scan_triggered",
  "scan_id": 123,
  "repository": "owner/repo",
  "branch": "main"
}
```

### GitLab

**Webhook URL:** `POST /api/webhooks/gitlab/{org_id}`

**Events:**
- **Push Hook** — Scan on push
- **Merge Request Hook** — Scan MR on open/update
- **Tag Push Hook** — Scan on tag push

**Setup:**
1. Project Settings → Webhooks
2. URL: `https://your-kryx.com/api/webhooks/gitlab/1`
3. Secret Token: (optional)
4. Triggers: Push, Merge request, Tag push

### Slack Notifications

**Setup:**
1. Create Slack app: https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Add webhook to workspace
4. Copy webhook URL

**API Endpoint:** `POST /api/integrations/slack/notify`

```json
{
  "slack_webhook_url": "https://hooks.slack.com/services/...",
  "message": "Critical vulnerability found!",
  "severity": "critical"
}
```

## Generic Webhooks

Configure custom webhooks for any service.

**Endpoint:** `POST /api/integrations/webhooks`

```json
{
  "webhook_url": "https://your-service.com/webhook",
  "events": ["scan.completed", "vuln.critical_found"]
}
```

**Events:**
- `scan.completed` — Scan finished
- `scan.failed` — Scan error
- `vuln.critical_found` — Critical vulnerability
- `vuln.high_found` — High severity vuln

**Payload Format:**
```json
{
  "event": "scan.completed",
  "timestamp": "2026-06-07T12:00:00Z",
  "data": {
    "scan_id": 123,
    "target": "https://github.com/user/repo",
    "vulns_found": 5,
    "critical": 1,
    "high": 2
  }
}
```

**Signature Verification:**

If `webhook_secret` configured, payloads are signed:

```
X-Kryx-Signature: sha256=<hmac_sha256(secret, payload)>
```

Verify:
```python
import hmac, hashlib

expected = "sha256=" + hmac.new(
    secret.encode(),
    payload.encode(),
    hashlib.sha256
).hexdigest()

if hmac.compare_digest(received_signature, expected):
    # Valid signature
```

## Testing

### Test Webhook

```bash
curl -X POST https://your-kryx.com/api/integrations/test-webhook \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://webhook.site/...",
    "events": ["scan.completed"]
  }'
```

### Test Slack

```bash
curl -X POST https://your-kryx.com/api/integrations/slack/notify \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "slack_webhook_url": "https://hooks.slack.com/services/...",
    "message": "Test notification from Kryx",
    "severity": "info"
  }'
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Kryx Scan
        run: |
          curl -X POST https://kryx.app/api/v2/scans \
            -H "Authorization: Bearer ${{ secrets.HEXOR_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "target": "${{ github.repository }}",
              "target_type": "repo"
            }'
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - |
      curl -X POST https://kryx.app/api/v2/scans \
        -H "Authorization: Bearer $HEXOR_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$CI_REPOSITORY_URL\", \"target_type\": \"repo\"}"
  only:
    - main
    - merge_requests
```

### Jenkins

```groovy
pipeline {
  agent any
  
  stages {
    stage('Security Scan') {
      steps {
        sh '''
          curl -X POST https://kryx.app/api/v2/scans \
            -H "Authorization: Bearer $HEXOR_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"target\": \"${GIT_URL}\", \"target_type\": \"repo\"}"
        '''
      }
    }
  }
}
```

## Best Practices

- ✅ Use API keys (not user tokens) for CI/CD
- ✅ Set up webhooks with retry logic
- ✅ Filter events to reduce noise
- ✅ Sign webhooks for security
- ✅ Use Slack for critical alerts only
- ✅ Monitor webhook delivery status

## Rate Limits

- Webhooks: 100/hour per org
- Slack notifications: 50/hour per org
- Test endpoints: 10/hour per org

---

**Need help?** Check logs in `/var/log/kryx/webhooks.log`
