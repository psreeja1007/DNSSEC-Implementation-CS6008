# Phase 2

Run from `phase2/`. Set `INTERCEPT_MODE=false` in `.env` for normal DNS.

```powershell
docker compose build
docker compose up -d
docker compose ps
docker exec core-router ip route get 172.16.2.10
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +noall +answer +stats
docker exec client dig '@172.16.2.10' www.example.com +noall +answer +stats
docker exec client curl -s --max-time 10 http://172.16.1.30/
```

Change `.env` to `INTERCEPT_MODE=true` to select monitor-only mode, then:

```powershell
docker compose up -d --force-recreate attacker
docker logs attacker
```

Stop the stack:

```powershell
docker compose down
```
