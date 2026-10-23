# Phase 5

Run from `phase5/`. Set `INTERCEPT_MODE=false` and `DENIAL_MODE=nsec` in `.env`.

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Walk the NSEC chain:

```powershell
@('example.com', 'admin.example.com', 'dev.example.com', 'domain-ns.example.com', 'git.example.com', 'mail.example.com', 'vpn.example.com', 'www.example.com') | ForEach-Object { docker compose exec client dig '@172.16.2.10' $_ TXT +dnssec +noall +comments +answer +authority }
```

For NSEC3, set `DENIAL_MODE=nsec3` and `NSEC3_SALT=a1b2c3d4` in `.env`, then rebuild:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Stop the stack:

```powershell
docker compose down
```
