# Hexor CLI

Command-line interface for Hexor AI-powered security scanning platform.

## Installation

```bash
pip install hexor
```

## Quick Start

### 1. Login

```bash
hexor login
# Enter your API key from https://hexor.app/settings/api
```

### 2. Run a Scan

```bash
# Scan local project
hexor scan /path/to/project

# Scan GitHub repository
hexor scan https://github.com/user/repo

# Scan website
hexor scan --type web https://example.com

# Scan without waiting for completion
hexor scan /path/to/project --no-wait
```

### 3. Check Status

```bash
hexor status 123
```

### 4. List Scans

```bash
hexor list
hexor list --limit 50
```

### 5. Get Report

```bash
# View in terminal
hexor report 123

# Save to file
hexor report 123 --output report.md

# JSON format
hexor report 123 --format json --output report.json
```

### 6. View Exploits

```bash
hexor exploits 123
```

## Commands

### `hexor login`

Save API credentials locally.

**Options:**
- `--api-key`: Your Hexor API key
- `--api-url`: API endpoint (default: https://api.hexor.app)

### `hexor scan <target>`

Start a new security scan.

**Arguments:**
- `target`: Path, URL, or repository to scan

**Options:**
- `--type`: Target type (`repo`, `source`, `web`) - default: `repo`
- `--wait/--no-wait`: Wait for completion - default: `True`

**Examples:**
```bash
hexor scan .
hexor scan /home/user/project
hexor scan https://github.com/org/repo
hexor scan --type web https://api.example.com
```

### `hexor status <scan_id>`

Check scan progress and status.

**Arguments:**
- `scan_id`: Scan ID number

**Example:**
```bash
hexor status 123
```

### `hexor list`

List recent scans.

**Options:**
- `--limit`: Number of scans to show (default: 20)

**Example:**
```bash
hexor list
hexor list --limit 100
```

### `hexor report <scan_id>`

Get full scan report.

**Arguments:**
- `scan_id`: Scan ID number

**Options:**
- `--format`: Output format (`markdown`, `json`) - default: `markdown`
- `--output, -o`: Save to file

**Examples:**
```bash
hexor report 123
hexor report 123 --output report.md
hexor report 123 --format json -o scan.json
```

### `hexor exploits <scan_id>`

List generated exploits.

**Arguments:**
- `scan_id`: Scan ID number

**Example:**
```bash
hexor exploits 123
```

## Configuration

Config file: `~/.hexor/config.json`

```json
{
  "api_key": "hx_...",
  "api_url": "https://api.hexor.app"
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Hexor CLI
        run: pip install hexor
      
      - name: Run Security Scan
        env:
          HEXOR_API_KEY: ${{ secrets.HEXOR_API_KEY }}
        run: |
          echo "$HEXOR_API_KEY" | hexor login --api-key $HEXOR_API_KEY
          hexor scan . --wait
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  script:
    - pip install hexor
    - echo "$HEXOR_API_KEY" | hexor login --api-key $HEXOR_API_KEY
    - hexor scan . --wait
  only:
    - main
    - merge_requests
```

## Development

### Install from source

```bash
git clone https://github.com/xxxoff/Hexor.git
cd Hexor/cli
pip install -e .
```

### Run tests

```bash
pytest tests/
```

## Support

- Documentation: https://docs.hexor.app
- Issues: https://github.com/xxxoff/Hexor/issues
- Email: support@hexor.app

## License

MIT License - see LICENSE file
