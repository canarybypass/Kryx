# CLI Testing Guide - Vulnyx

## Backend Status
✅ Backend running on http://localhost:8000

## Testing Commands

### 1. Login to Vulnyx
```bash
cd /home/offsys/hexor/cli
python3 vulnyx_cli.py login --api-key demo_key_123
```

### 2. Create a Scan
```bash
python3 vulnyx_cli.py scan https://github.com/example/vulnerable-app --wait
```

### 3. List Scans
```bash
python3 vulnyx_cli.py list
```

### 4. Check Scan Status
```bash
python3 vulnyx_cli.py status 1
```

### 5. Get Report
```bash
python3 vulnyx_cli.py report 1
```

### 6. View Exploits
```bash
python3 vulnyx_cli.py exploits 1
```

## Expected Results

1. **Login**: Should create `~/.vulnyx/config.json`
2. **Scan**: Should create scan and show progress
3. **List**: Should show scan history
4. **Status**: Should show scan details and pipeline progress
5. **Report**: Should show vulnerability report
6. **Exploits**: Should list generated exploits

## Troubleshooting

If backend is not running:
```bash
cd /home/offsys/hexor/backend
python3 test_api.py > /tmp/vulnyx_backend.log 2>&1 &
```

Check backend logs:
```bash
tail -f /tmp/vulnyx_backend.log
```

Check backend health:
```bash
curl http://localhost:8000/health
```

## Test Files

- CLI location: `/home/offsys/hexor/cli/vulnyx_cli.py`
- Backend location: `/home/offsys/hexor/backend/test_api.py`
- Config file: `~/.vulnyx/config.json`
