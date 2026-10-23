# Phase 4

Run from `phase4/`. For the signed baseline and Run A, set:

```dotenv
ATTACK_MODE=normal
INSERT_CHILD_DS=true
```

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
```

Run A: set `ATTACK_MODE=strip` and keep `INSERT_CHILD_DS=true` in `.env`.

```powershell
docker compose up -d --force-recreate core-router attacker
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
```

Run B: set `ATTACK_MODE=strip` and `INSERT_CHILD_DS=false` in `.env`, then rebuild the chain:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' DS example.com +dnssec +noall +comments +answer +authority
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
docker exec client curl -i --max-time 10 http://example.com/
```

Stop the stack:

```powershell
docker compose down
```
