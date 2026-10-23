# Phase 7

Run from `phase7/`. Set `ATTACK=none` in `.env`.

```powershell
docker compose build
docker compose up -d
docker compose ps
docker exec client env POSTURE=strict TRANSPORT=dot /usr/local/bin/resolve.sh example.com
docker exec client env POSTURE=strict TRANSPORT=doh /usr/local/bin/resolve.sh example.com
```

For each attack, set `ATTACK=alter`, `ATTACK=rogue-cert`, or `ATTACK=block` in `.env`:

```powershell
docker compose up -d --force-recreate edge-router attacker
docker exec client env POSTURE=strict TRANSPORT=dot /usr/local/bin/resolve.sh example.com
docker exec client-b env POSTURE=permissive TRANSPORT=dot /usr/local/bin/resolve.sh example.com
docker logs edge-router
docker logs attacker
```

For a forged fallback, fetch the rogue page:

```powershell
docker exec client-b curl -s --resolve example.com:80:172.16.1.30 http://example.com/
```

Stop the stack:

```powershell
docker compose down
```
