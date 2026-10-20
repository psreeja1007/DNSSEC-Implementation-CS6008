# Phase 1 — Building the DNS Hierarchy

This brings up the full 8-container baseline: a 3-tier DNS hierarchy
(root-ns → tld-ns → domain-ns), a recursive resolver, a client, a
webserver, and the two routers that connect the three isolated subnets.
No attacker yet — this is the known-good baseline Phase 2+ builds on.

## 0. Prerequisites

- Docker Engine or Docker Desktop, with Compose v2 (`docker compose`, not
  the old `docker-compose`).
- Ability to run containers with `NET_ADMIN` (rootless/locked-down Docker
  may refuse this — use a standard Docker install).

## 1. Directory layout

```
phase1/
├── compose.yml
├── root-ns/        # authoritative for "."
├── tld-ns/          # authoritative for "com"
├── domain-ns/       # authoritative for "example.com"
├── resolver/        # recursive caching resolver
├── client/          # end host (dig/curl/tcpdump)
├── webserver/        # serves the real example.com page
├── edge-router/       # client subnet <-> resolver subnet
└── core-router/        # resolver subnet <-> authoritative subnet
```

Each service directory has its own `Dockerfile` + `entrypoint.sh`, plus
`named.conf`/zone files for the DNS containers.

## 2. Deploy

From inside `phase1/`:

```bash
docker compose build
docker compose up -d
docker compose ps
```

All 8 containers should show as `running`. Check each one applied its
static route(s) correctly:

```bash
docker logs root-ns      | grep -A3 routes
docker logs tld-ns       | grep -A3 routes
docker logs domain-ns    | grep -A3 routes
docker logs resolver     | grep -A3 routes
docker logs client       | grep -A3 routes
docker logs edge-router  | grep -A3 interfaces
docker logs core-router  | grep -A3 interfaces
```

## 3. Verify

### 3.1 Resolution works end to end

```bash
docker exec client dig +short example.com
# expect: 172.16.1.20

docker exec client dig +short www.example.com
# expect: 172.16.1.20

docker exec client curl -s http://example.com
# expect: the "REAL example.com" HTML page
```

### 3.2 Subnet isolation holds

```bash
docker exec client dig +short @172.16.3.10 example.com +time=2 +tries=1
# expect: no answer / timeout — client has no route to the
# authoritative subnet; only resolver and core-router do.
```

### 3.3 Capture one full resolution on core-router

Flush the resolver's cache first so you actually see the referral
chain instead of a cached answer:

```bash
docker exec resolver rndc flush

# start capture on core-router in one terminal
docker exec core-router tcpdump -i any -w /tmp/phase1-referral.pcap udp port 53 &

# trigger a fresh lookup from the client in another terminal
docker exec client dig example.com

# stop the capture
docker exec core-router pkill tcpdump

# pull the capture out for Wireshark/tshark inspection
docker cp core-router:/tmp/phase1-referral.pcap ./phase1-referral.pcap
```

Open `phase1-referral.pcap` in Wireshark (or `tshark -r
phase1-referral.pcap`) and identify the three separate exchanges:
resolver↔root-ns (referral to `com.`), resolver↔tld-ns (referral to
`example.com.`), resolver↔domain-ns (the actual A record answer).

## 4. Tear down / reset

```bash
docker compose down          # stop and remove containers
docker exec resolver rndc flush   # clear resolver cache without a restart
```

## 5. Notes for the report

- Keep the terminal output of §3.1–3.2 and the annotated capture from
  §3.3 — these are the Phase 1 deliverables.
- For the "what could an on-path node do" report question: note that
  every exchange you just captured was plaintext UDP with no
  authentication — any node on the resolver's path (like core-router's
  position) could read every query/answer, and nothing stops it from
  injecting its own forged answer first. That's exactly what Phase 2
  does.
- All private key / signing material doesn't apply yet (Phase 3+).

## 6. What's deliberately left simple here (by design, revisited later)

- `dnssec-validation no` on the resolver — DNSSEC arrives in Phase 3.
- BIND runs as root inside each container for simplicity in this
  isolated lab; not a production practice.
- No rndc key / TSIG is configured since there's no zone transfer in
  this phase.
