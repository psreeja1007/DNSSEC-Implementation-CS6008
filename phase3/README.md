# Phase 3

Run from `phase3/`. Set `INTERCEPT_MODE=false` in `.env`.

```powershell
docker compose build
docker compose up -d
docker compose ps
docker logs -f domain-ns
docker logs -f tld-ns
docker logs -f root-ns
docker logs -f resolver
```

Verify DNSSEC:

```powershell
docker exec core-router ip route get 172.16.2.10
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com +rtrace
```

Set `INTERCEPT_MODE=true` in `.env` to test the attack:

```powershell
docker compose up -d --force-recreate core-router attacker
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +dnssec +noall +comments +answer +stats
docker exec client curl -s --max-time 10 http://example.com/
```

Stop the stack:

```powershell
docker compose down
```
