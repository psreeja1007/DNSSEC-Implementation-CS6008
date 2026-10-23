# Phase 6

Run from `phase6/`. Set `INTERCEPT_MODE=false` in `.env` for transparent relay.

```powershell
docker compose build
docker compose up -d
docker compose ps
docker compose up -d --force-recreate edge-router attacker
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +short
docker exec client-b delv -a /pki/root-anchor.conf '@172.16.2.10' example.com
```

Set `INTERCEPT_MODE=true` in `.env` to test forgery:

```powershell
docker compose up -d --force-recreate edge-router attacker
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +short
docker exec client curl -s --max-time 10 http://example.com/
docker exec client-b delv -a /pki/root-anchor.conf '@172.16.2.10' example.com
docker logs attacker
```

Stop the stack:

```powershell
docker compose down
```
