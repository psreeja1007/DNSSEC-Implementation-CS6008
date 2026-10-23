# Phase 7 — Encrypting the Last Mile (DoT / DoH)

Phase 6 showed the resolver→client hop is forgeable. This phase authenticates
and encrypts that hop with **DoT (TCP 853)** and **DoH (TCP 443)**, backed by a
private CA, then mounts the last-mile attack again from three angles and
accounts for each result against two client postures.

## What changed from Phase 6

- **Private CA + resolver certificate.** The resolver stands up a private CA at
  startup and issues itself a cert with **SAN `DNS:resolver.cs6008.local` only
  (no IP SAN)**. It publishes the CA cert (`/pki/ca.pem`) for the clients; the
  CA key and server key never leave the resolver and are never committed.
- **Reach the resolver by name.** Clients carry `resolver.cs6008.local →
  172.16.2.10` in `extra_hosts` and connect **by name**, validating the cert
  against the CA and that hostname. No `-k` / insecure bypass anywhere.
- **Encrypted transports.** BIND listens DoT on 853 and DoH on 443 (`tls` +
  `http` statements in `resolver/named.conf`). Cleartext Do53 stays up so we can
  model a client that *tolerates* a downgrade.
- **Two client postures** (`resolve.sh`, `POSTURE=`):
  - **Client A / `client` / 172.16.1.10 — refuses cleartext (strict DoT).**
  - **Client B / `client-b` / 172.16.1.11 — permits cleartext fallback.**
- Upstream (resolver↔authoritative) and DNSSEC validation are unchanged.

## Deploy (7.1)

```powershell
# .env: ATTACK=none
docker compose build
docker compose up -d
docker logs -f resolver   # shows CA/cert generation + the DNSSEC trust anchor
```

The resolver log prints the issued cert's subject and `X509v3 Subject
Alternative Name: DNS:resolver.cs6008.local`.

## Verify (7.2) — clean encrypted resolution

```powershell
# DoT, validating against the lab CA + hostname, by name:
docker exec client   env POSTURE=strict TRANSPORT=dot /usr/local/bin/resolve.sh example.com
# DoH over 443:
docker exec client   env POSTURE=strict TRANSPORT=doh /usr/local/bin/resolve.sh example.com
```

Expect `example.com A 172.16.1.20`, the `ad` flag set (upstream DNSSEC still
holds), `[result] encrypted transport SUCCEEDED`, and a clean certificate
validation. Fetch the real page over the validated address:

```powershell
docker exec client curl -s --resolve example.com:80:172.16.1.20 http://example.com/
```

Confirm **no cleartext DNS** on the wire for the lookup — capture on
edge-router and check there is traffic on 853/443 but nothing on 53:

```powershell
docker exec edge-router tcpdump -ni any -c 20 'tcp port 853 or tcp port 443 or udp port 53'
```

## Attacks (7.3) — three attempts × two postures

Each attempt is selected in `.env` and applied by recreating the two nodes that
implement it. Run **both** clients for each.

```powershell
# edit .env -> ATTACK=<alter|rogue-cert|block>, then:
docker compose up -d --force-recreate edge-router attacker
docker logs edge-router      # shows the diversion that was installed
```

Then, for each attempt:

```powershell
# Client A — refuses cleartext (strict)
docker exec client   env POSTURE=strict     TRANSPORT=dot /usr/local/bin/resolve.sh example.com
# Client B — permits cleartext fallback
docker exec client-b env POSTURE=permissive TRANSPORT=dot /usr/local/bin/resolve.sh example.com
```

When Client B reports a forged answer (`172.16.1.30`), show it landing on the
rogue page:

```powershell
docker exec client-b curl -s --resolve example.com:80:172.16.1.30 http://example.com/
```

### (i) `ATTACK=alter` — alter the answer in transit
The attacker corrupts a byte inside the DoT **application-data** record on the
return path (`interceptor` `tamper853`). TLS's record authentication fails and
the connection aborts. The cleartext fallback (if any) is forged (`forge53`).

### (ii) `ATTACK=rogue-cert` — impersonate the resolver
The edge-router redirects 853/443 to the attacker's `openssl s_server`, which
presents a **self-signed cert not issued by the lab CA**. The client's
CA+hostname validation rejects it.

### (iii) `ATTACK=block` — deny the encrypted transport
The edge-router DROPs TCP 853/443, forcing clients to either fail (strict) or
downgrade to cleartext (permissive, then forged).

## Results — the six combinations

| Attempt | Client A (refuses cleartext) | Client B (permits cleartext) |
|---|---|---|
| (i) alter in transit | **Does not land.** TLS record check fails → DoT aborts → no answer (fails closed). | **Lands.** DoT aborts → downgrades to Do53 → forged → `172.16.1.30`. |
| (ii) rogue certificate | **Does not land.** Cert is not CA-issued → validation fails → no answer. | **Lands.** Cert rejected → downgrades to Do53 → forged → `172.16.1.30`. |
| (iii) deny transport | **Does not land.** 853/443 unreachable → no answer (fails closed). | **Lands.** Can't reach DoT → downgrades to Do53 → forged → `172.16.1.30`. |

The pattern: **encryption + authentication stops all three attacks for the
strict client**; the permissive client is defeated in every case, because the
attacker only has to make the encrypted transport *fail* (corrupt it, present a
bad cert, or block the port) and then forge the cleartext the client is willing
to accept.

## Evidence to capture

Per attempt, under `evidence/`:
- `docker logs edge-router` (the installed diversion) and `docker logs attacker`
  (the `tamper853` / `forge53` lines).
- Client A output showing failure (no answer / `certificate verify failed` /
  connection aborted).
- Client B output showing the forged `172.16.1.30` and the rogue page fetch.
- An edge-router capture of the attempted encrypted exchange and cleartext
  fallback: `tcpdump -ni any -w /tmp/phase7-<attack>-edge.pcap 'tcp port 853
  or tcp port 443 or udp port 53'`.
- A Client B capture of the actual forged fallback response:
  `tcpdump -ni eth0 -w /tmp/phase7-<attack>-client-b.pcap 'udp port 53'`.

The edge-router capture sees the resolver's reply before the attacker rewrites
it. The interceptor injects the modified DNS frame directly to Client B, so
capture at the client to preserve proof of the forged answer itself.

## Report (7.4) — pointers

- **Per attempt × client:** use the table above; back each cell with its log +
  capture.
- **DoT vs DoH.** We deployed **DoT** as the primary last-mile transport (and
  also enabled DoH). DoT on its dedicated port 853 is simple and cleanly
  visible/blockable — which also makes it *easy to censor* (attack iii): an
  on-path party can DROP 853 outright. DoH hides DNS inside ordinary HTTPS on
  443, so it resists that port-blocking/censorship and traffic analysis better,
  but it is heavier (HTTP/2 framing), harder to monitor for legitimate
  operators, and 443 cannot simply be blocked without taking down the web.
- **What an encrypted, authenticated last mile still does NOT protect:**
  - A client that accepts an **unauthenticated downgrade** — the whole point of
    the Client B results. Encryption is worthless if cleartext is still
    acceptable; the client must refuse it (strict/`Strict` DoT).
  - **Metadata / traffic analysis** — DoT's dedicated port, SNI, timing and
    packet sizes can still leak which site is being visited.
  - **The resolver↔authoritative path and the resolver's own integrity** — this
    hop secures only client↔resolver; it does not replace DNSSEC upstream, nor
    does it vouch for what the resolver itself returns.
  - **Availability** — blocking 853/443 is itself an attack (iii); encryption
    does not guarantee the client can resolve at all.

## Privilege / isolation notes

- `edge-router`: `NET_ADMIN`, `ip_forward=1` — holds the routing, policy-routing
  and the per-attack iptables diversion (the DNAT/MASQUERADE in attack ii and
  the DROP in attack iii are the *attack*, not the lab's normal forwarding,
  which stays no-NAT).
- `attacker`: `NET_RAW` (libpcap) + `NET_ADMIN`; `ip_forward=0` — it does not
  route. The interceptor is the only relay; `openssl s_server` only terminates
  the diverted TLS to present the rogue cert.
- No private keys committed: `common/pki/` tracks only `.gitkeep`. The CA key,
  resolver key, and the attacker's rogue key are generated inside their
  containers at startup.
