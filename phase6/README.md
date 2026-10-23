# Phase 6 — Last-Mile Response Forgery

The resolver validates DNSSEC (Phase 3), but the hop from **resolver → client**
carries no proof of that validation: a stub client trusts whatever appears to
come from its resolver. This phase moves the adversary off the resolver subnet
and onto the **client's last mile** and forges the reply there, below where
DNSSEC's guarantee ends.

## What changed from Phase 3

| | Phase 3 | Phase 6 |
|---|---|---|
| Attacker location | resolver subnet, `172.16.2.100` | **client subnet, `172.16.1.100`** |
| Diversion point | `core-router` (resolver-bound replies) | **`edge-router`** (client-bound replies) |
| Interceptor relays toward | the resolver | **the client(s)** |
| Clients | one stub | **Client A (stub) + Client B (validating)** |
| Upstream (resolver ↔ auth) | — | **untouched** |

The signed hierarchy, the validating resolver, the trust-anchor plumbing, and
the signing scripts are all carried over from Phase 3 verbatim. The attacker's
C++ interceptor is the same pure-libpcap design (`pcap_loop` + `pcap_inject`,
no NFQUEUE, no raw sockets); it is retargeted to re-address relayed frames
toward the client rather than the resolver.

Two clients are provisioned so the report can contrast them:

- **Client A** (`client`, `172.16.1.10`) — ordinary stub: `curl` / the OS
  resolver. It trusts the resolver's reply, so it lands on the rogue page.
- **Client B** (`client-b`, `172.16.1.11`) — validates locally with `delv`
  against the root KSK as its **own** trust anchor. It checks signatures
  itself, so it catches the forgery.

## How the forgery reaches each client

`edge-router` installs a host route per client that points at the attacker:

```
ip route replace 172.16.1.10/32 via 172.16.1.100   # Client A
ip route replace 172.16.1.11/32 via 172.16.1.100   # Client B
```

A `resolver → client` reply crossing the edge-router is therefore handed to the
attacker at L2 (Ethernet dst = attacker's MAC) while its IP destination is
still the client. The attacker keeps `ip_forward=0`, so the kernel never
relays it automatically — the `interceptor` program is the router hop: it
captures the frame, (optionally) rewrites the `example.com` A record to
`172.16.1.30` (rogue-web), recomputes checksums, re-stamps the Ethernet
header toward the real client, and injects it. The client's own routing and
`resolv.conf` are never touched (no ARP spoofing).

The edge-router always installs these diversion routes. `INTERCEPT_MODE`
controls only whether the attacker rewrites the DNS answer; when it is `false`,
the attacker still relays replies unchanged.

Only the **A rdata** is rewritten — the RRSIG that still covers the genuine
`172.16.1.20` is left in place. Client A does not look at it; Client B's local
validation does, and the mismatch is what trips the forgery.

## Deploy (6.1)

Run from `phase6/`. Stop earlier phases first if container/network names clash.
The client-bound diversion is active in both modes; the default
`INTERCEPT_MODE=false` is the transparent-relay verification mode.

```powershell
docker compose build
docker compose up -d
docker compose ps
```

As in Phase 3, each nameserver generates keys and signs its zone at startup and
waits on the DS from the one below it; give it a minute and watch:

```powershell
docker logs -f domain-ns
docker logs -f resolver   # ends with the trust-anchors { . } block before BIND starts
```

## Verify (6.2) — transparent relay, forging OFF

Keep `INTERCEPT_MODE=false` in `.env` and confirm both clients still get the
real answer and page through the automatically armed diversion:

```powershell
# .env: INTERCEPT_MODE=false
docker compose up -d --force-recreate edge-router attacker
docker exec edge-router ip route            # host routes for .10/.11 via 172.16.1.100

docker exec resolver rndc flush

# Client A — ordinary stub
docker exec client dig '@172.16.2.10' example.com +short         # -> 172.16.1.20
docker exec client curl -s --max-time 10 http://example.com/     # real page

# Client B — validates locally against the root KSK
docker exec client-b delv -a /pki/root-anchor.conf '@172.16.2.10' example.com
# -> "; fully validated" with A 172.16.1.20
```

`docker logs attacker` shows `[relay] ... (unchanged)` lines — every reply is
passing through the attacker, untouched.

## Attack (6.3) — forging ON

```dotenv
INTERCEPT_MODE=true
```

```powershell
docker compose up -d --force-recreate edge-router attacker
docker exec resolver rndc flush
```

### Client A (ordinary stub) — should be fooled

```powershell
docker exec client dig '@172.16.2.10' example.com +short         # -> 172.16.1.30 (rogue)
docker exec client curl -s --max-time 10 http://example.com/     # rogue/defacement page
```

### Client B (locally validating) — should refuse

```powershell
docker exec client-b delv -a /pki/root-anchor.conf '@172.16.2.10' example.com
# -> validation fails: "no valid RRSIG" / "insecurity proof failed" / SERVFAIL;
#    delv does NOT hand back 172.16.1.30.
```

`docker logs attacker` now shows the `[DNS match] ... forged to 172.16.1.30
(RRSIG left untouched)` line for each client's `example.com` lookup, and plain
`[relay]` lines for everything else (e.g. `www.example.com`), proving
non-target names are untouched.

## Evidence to capture for the report

Capture the diverted packet on `edge-router` and the actual modified reply on
each receiving client. The edge-router capture shows the resolver's reply
leaving toward the attacker; the rewritten frame is injected directly onto the
client network and does not pass back through the edge-router.

```powershell
# Start captures in separate terminals before running the attack lookups.
docker exec edge-router tcpdump -U -ni any -w /tmp/p6-edge.pcap 'udp port 53 or arp'
docker exec client tcpdump -U -ni eth0 -w /tmp/p6-client-a.pcap 'udp port 53'
docker exec client-b tcpdump -U -ni eth0 -w /tmp/p6-client-b.pcap 'udp port 53'

# After the lookups, stop each capture with Ctrl+C and copy them out.
docker cp edge-router:/tmp/p6-edge.pcap ./evidence/phase6-edge.pcap
docker cp client:/tmp/p6-client-a.pcap ./evidence/phase6-client-a.pcap
docker cp client-b:/tmp/p6-client-b.pcap ./evidence/phase6-client-b.pcap
```

Put under `evidence/`: attacker logs (`docker logs attacker`), the Client A
`dig`/`curl` output showing `172.16.1.30` + rogue page, the Client B `delv`
output showing validation failure, and the annotated captures. The client
captures show the forged answer as received and the stale RRSIG that Client B
rejects.

## Report (6.4) — pointers

- **Outcome per client.** A lands on rogue-web; B refuses. Show both.
- **Why DNSSEC doesn't stop this.** Validation happens at the *resolver*; trust
  on the stub is placed in *the resolver + the link to it*. The forgery is
  injected on that unprotected link, downstream of where any signature was
  checked. DNSSEC authenticates resolver↔authoritative data, not resolver↔stub
  delivery.
- **The `ad` flag.** `ad` (authenticated-data) is just a header bit the resolver
  sets to say "I validated this." It is not signed and not bound to the client,
  so an on-path attacker rewriting the reply can set or keep it at will — it is
  a claim, not a proof. Client B ignores `ad` and re-validates the signatures
  itself with its own trust anchor, so the stale RRSIG over `172.16.1.20` fails
  to cover the forged `172.16.1.30` and B rejects the answer. That — local
  validation, not trusting a flag — is what Phase 7 then protects in transit by
  encrypting and authenticating the last mile.

## Notes on privilege / isolation

- `edge-router` keeps `NET_ADMIN` + `ip_forward=1` (it is a router and holds the
  diversion route). `attacker` keeps only `NET_RAW` (libpcap capture/inject)
  with `ip_forward=0` — it does not forward, bridge, or NAT.
- No private keys are committed; `common/pki/` tracks only `.gitkeep`. Key
  material and signed zones are generated inside the containers at startup, as
  in Phase 3.
