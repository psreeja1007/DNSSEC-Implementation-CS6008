# Phase 1

Run from `phase1/`:

```powershell
docker compose build
docker compose up -d
docker compose ps
docker exec client dig +short example.com
docker exec client dig +short www.example.com
docker exec client curl -s http://example.com/
```

Check BIND and network setup:

```powershell
docker exec root-ns named -v
docker exec tld-ns named -v
docker exec domain-ns named -v
docker exec resolver named -v
docker exec client dig +short @172.16.3.10 example.com +time=2 +tries=1
```

Stop the stack:

```powershell
docker compose down
```
