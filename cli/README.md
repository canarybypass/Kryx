# Kryx CLI

Command-line interface for Kryx AI-powered security scanning platform.

## Installation

```bash
pip install kryx
```

## Quick Start

### 1. Login

```bash
kryx login
# Enter your API key from https://kryx.app/settings/api
```

### 2. Run a Scan

```bash
# Scan local project
kryx scan /path/to/project

# Scan GitHub repository
kryx scan https://github.com/user/repo

# Scan website
kryx scan --type web https://example.com

# Scan without waiting for completion
kryx scan /path/to/project --no-wait
```

### 3. Check Status

```bash
kryx status 123
```

### 4. List Scans

```bash
kryx list
kryx list --limit 50
```

### 5. Get Report

```bash
# View in terminal
kryx report 123

# Save to file
kryx report 123 --output report.md

# JSON format
kryx report 123 --format json --output report.json
```

### 6. View Exploits

```bash
kryx exploits 123
```

## Commands

### `kryx login`

Save API credentials locally.

**Options:**
- `--api-key`: Your Kryx API key
- `--api-url`: API endpoint (default: https://api.kryx.app)

### `kryx scan <target>`

Start a new security scan.

**Arguments:**
- `target`: Path, URL, or repository to scan

**Options:**
- `--type`: Target type (`repo`, `source`, `web`) - default: `repo`
- `--wait/--no-wait`: Wait for completion - default: `True`

**Examples:**
```bash
kryx scan .
kryx scan /home/user/project
kryx scan https://github.com/org/repo
kryx scan --type web https://api.example.com
```

### `kryx status <scan_id>`

Check scan progress and status.

**Arguments:**
- `scan_id`: Scan ID number

**Example:**
```bash
kryx status 123
```

### `kryx list`

List recent scans.

**Options:**
- `--limit`: Number of scans to show (default: 20)

**Example:**
```bash
kryx list
kryx list --limit 100
```

### `kryx report <scan_id>`

Get full scan report.

**Arguments:**
- `scan_id`: Scan ID number

**Options:**
- `--format`: Output format (`markdown`, `json`) - default: `markdown`
- `--output, -o`: Save to file

**Examples:**
```bash
kryx report 123
kryx report 123 --output report.md
kryx report 123 --format json -o scan.json
```

### `kryx exploits <scan_id>`

List generated exploits.

**Arguments:**
- `scan_id`: Scan ID number

**Example:**
```bash
kryx exploits 123
```

## Configuration

Config file: `~/.kryx/config.json`

```json
{
  "api_key": "hx_...",
  "api_url": "https://api.kryx.app"
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
      
      - name: Install Kryx CLI
        run: pip install kryx
      
      - name: Run Security Scan
        env:
          HEXOR_API_KEY: ${{ secrets.HEXOR_API_KEY }}
        run: |
          echo "$HEXOR_API_KEY" | kryx login --api-key $HEXOR_API_KEY
          kryx scan . --wait
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  script:
    - pip install kryx
    - echo "$HEXOR_API_KEY" | kryx login --api-key $HEXOR_API_KEY
    - kryx scan . --wait
  only:
    - main
    - merge_requests
```

## Development

### Install from source

```bash
git clone https://github.com/xxxoff/Kryx.git
cd Kryx/cli
pip install -e .
```

### Run tests

```bash
pytest tests/
```

## Support

- Documentation: https://docs.kryx.app
- Issues: https://github.com/xxxoff/Kryx/issues
- Email: support@kryx.app

## License

MIT License - see LICENSE file
