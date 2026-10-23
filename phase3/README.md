# Phase 3 - DNSSEC Chain of Trust

Carries over Phase 2 unchanged: the full DNS hierarchy, the rogue web server
(`172.16.1.30`), and the attacker (`172.16.2.100`) with its Phase 2
interceptor binary. The only things that change are the authoritative zones
(now DNSSEC-signed, chained with DS records) and the resolver (now validates).

## How signing works here

Signing happens **inside each nameserver container at startup**, not at
image-build time, and signed zones / private keys are never written to the
host or committed: each `K*.key` / `K*.private` pair is generated once by
`dnssec-keygen` inside that container's own writable filesystem layer and
simply disappears when the container is removed.

The three authoritative servers need to hand DS records to one another
(domain-ns -> tld-ns -> root-ns) and root-ns needs to hand its KSK to the
resolver and client. They do this through a small shared bind mount,
`./common/pki`, mounted as `/pki` in root-ns, tld-ns, domain-ns, resolver,
and client. Each
`entrypoint.sh` waits (polling, up to ~2 minutes) for the file it depends on
before signing:

```
domain-ns  --(example.com.ds)-->  tld-ns  --(com.ds)-->  root-ns  --(root.key)-->  resolver
```

`common/pki/` ignores generated key material and DS files; only `.gitkeep` is
tracked. The client mounts this directory read-only so `delv` can validate
using the published root KSK without copying private signing keys out of their
authoritative containers.

## Deploy

Run the following commands from `phase3/`. Stop Phase 2 first if it is
running with colliding container/network names.

```powershell
docker compose build
docker compose up -d
docker compose ps
```

If Docker Desktop reports `invalid file request Dockerfile` while building
from this OneDrive-backed workspace, use its legacy-builder compatibility
mode for that build:

```powershell
$env:DOCKER_BUILDKIT = "0"
docker compose build
Remove-Item Env:DOCKER_BUILDKIT
```

Startup takes longer than Phase 1/2 the first time, since each nameserver is
generating keys and signing its zone, and each later one is waiting on the
DS from the one before it. Watch it happen:

```powershell
docker logs -f domain-ns
docker logs -f tld-ns
docker logs -f root-ns
docker logs -f resolver
```

`resolver`'s log should end with the `trust-anchors { ... };` block it built
from `root-ns`'s KSK, right before BIND starts.

## Verify (3.2) -- before attacking

Make sure `INTERCEPT_MODE=false` in `.env`. Apply the setting to the router
(which reads it at startup) and verify the normal route:

```powershell
docker compose up -d --force-recreate core-router
docker exec core-router ip route get 172.16.2.10
```

Then check the resolver returns an authenticated answer:

```powershell
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +dnssec +noall +comments +answer +stats
```

Look for `ad` in the flags shown in the comments/header and an `RRSIG` record
alongside the `A` record.

Validate the full chain independently of the resolver's own `ad` flag. `delv`
uses the root KSK published by root-ns as its sole trust anchor:

```powershell
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com +rtrace
```

The shared mount exposes only the root KSK and a `delv`-formatted copy to the
client; private keys remain in the authoritative server containers.

## Signing algorithm and key handling

All three zones use ECDSA P-256 with SHA-256 (DNSSEC algorithm 13). It gives
compact public keys and signatures and lower signing/verification cost than
RSA, while RSA remains a more widely compatible alternative in older DNSSEC
implementations. The private KSK/ZSK files are generated inside their
authoritative containers and must not be submitted or committed.

## Attack (3.3) -- re-run Phase 2 unchanged

```dotenv
INTERCEPT_MODE=true
```

```powershell
docker compose up -d --force-recreate core-router attacker
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +dnssec +noall +comments +answer +stats
docker exec client curl -s --max-time 10 http://example.com/
```

Expect the forged answer to be **rejected**: either SERVFAIL / no answer, or
(if the interceptor fails to forge a consistent signed response) the
resolver falls back to the real, validated `172.16.1.20`. Capture this on
`core-router` alongside the Phase 1/2 captures for the report.
