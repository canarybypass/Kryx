# CLI Testing Guide - Kryx

## Backend Status
✅ Backend running on http://localhost:8000

## Testing Commands

### 1. Login to Kryx
```bash
cd /home/offsys/kryx/cli
python3 kryx_cli.py login --api-key demo_key_123
```

### 2. Create a Scan
```bash
python3 kryx_cli.py scan https://github.com/example/vulnerable-app --wait
```

### 3. List Scans
```bash
python3 kryx_cli.py list
```

### 4. Check Scan Status
```bash
python3 kryx_cli.py status 1
```

### 5. Get Report
```bash
python3 kryx_cli.py report 1
```

### 6. View Exploits
```bash
python3 kryx_cli.py exploits 1
```

## Expected Results

1. **Login**: Should create `~/.kryx/config.json`
2. **Scan**: Should create scan and show progress
3. **List**: Should show scan history
4. **Status**: Should show scan details and pipeline progress
5. **Report**: Should show vulnerability report
6. **Exploits**: Should list generated exploits

## Troubleshooting

If backend is not running:
```bash
cd /home/offsys/kryx/backend
python3 test_api.py > /tmp/kryx_backend.log 2>&1 &
```

Check backend logs:
```bash
tail -f /tmp/kryx_backend.log
```

Check backend health:
```bash
curl http://localhost:8000/health
```

## Test Files

- CLI location: `/home/offsys/kryx/cli/kryx_cli.py`
- Backend location: `/home/offsys/kryx/backend/test_api.py`
- Config file: `~/.kryx/config.json`
