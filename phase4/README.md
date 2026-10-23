# Phase 4 - DNSSEC Downgrade Demonstration

Phase 4 reuses the signed root -> `.com` -> `example.com` hierarchy and the
validating resolver. The attacker has no signing keys. In `strip` mode it
relays DNS responses while removing `example.com` DS/DNSKEY data and `example.com` RRSIG records other than the NSEC denial signature; it then replaces the `example.com` A answer
with the rogue server address (`172.16.1.30`). It preserves signed NSEC proofs
and their signatures, which are needed to validate that the parent has no DS
in Run B. The interceptor changes selected DNSSEC RR types to a private-use
unknown type rather than shifting packet data; this hides those records from
DNSSEC validation while keeping DNS compression pointers valid.

`ATTACK_MODE` is shared by `core-router` and `attacker`:

- `normal`: direct resolver routing; attacker relays nothing.
- `intercept`: divert resolver traffic and replace the A answer.
- `strip`: divert resolver traffic, remove target DNSSEC records, and forge A.

`INSERT_CHILD_DS` controls whether `tld-ns` inserts the signed child's DS into
the signed `com` zone. Leave it `true` except for Run B.

## 4.1 Deploy and establish the signed baseline

Run commands from `phase4/`. In `.env`, use:

```dotenv
ATTACK_MODE=normal
INSERT_CHILD_DS=true
```

Start with clean DNSSEC handoff files so every zone and trust anchor is built
from this run's keys:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
```

Wait for the nameserver startup sequence to finish:

```powershell
docker logs -f domain-ns
docker logs -f tld-ns
docker logs -f root-ns
docker logs -f resolver
```

The logs should show the child DS inserted into `com`, the `com` DS inserted
into the root zone, and the root KSK installed as the resolver trust anchor.
Stop following the logs with Ctrl+C after startup.

Before attacking, flush the resolver and confirm the signed answer and chain:

```powershell
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
```

Expect `172.16.1.20`, an `RRSIG` in the `dig` answer, and `fully validated`
from `delv`. This is the authenticated baseline used before both attacks.

## 4.2 Run A - strip records from a securely delegated child

Keep the signed parent/child relationship and change `.env` to:

```dotenv
ATTACK_MODE=strip
INSERT_CHILD_DS=true
```

Recreate the router and attacker so they read the new mode:

```powershell
docker compose up -d --force-recreate core-router attacker
docker exec core-router ip route get 172.16.2.10
docker logs attacker
```

The route should use `172.16.2.100` as its gateway and the attacker should log
`mode: strip`. In another terminal, capture the resolver-facing DNS traffic:

```powershell
docker exec attacker tcpdump -ni eth0 -w /tmp/run-a.pcap udp port 53
```

While the capture runs, query the resolver (flush before each new test):

```powershell
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
docker exec client curl -i --max-time 10 http://example.com/
```

Stop `tcpdump` with Ctrl+C, then copy and save logs/capture for the report:

```powershell
docker cp attacker:/tmp/run-a.pcap .\run-a.pcap
docker logs --since 10m attacker | Tee-Object .\run-a-attacker.log
docker logs --since 10m resolver | Tee-Object .\run-a-resolver.log
docker logs --since 10m core-router | Tee-Object .\run-a-core-router.log
```

Record the actual resolver result. With the secure DS delegation intact, the
resolver must not return the forged address as a validated answer; expect a
validation failure such as SERVFAIL/no answer. Stripping a DS or its signature
does not provide a valid signed proof that no DS exists. The resolver already
has a trust path from its root anchor through the signed `com` zone, so missing
or inconsistent child validation data is treated as bogus, not as permission
to accept unsigned data.

## 4.3 Run B - signed child, missing parent DS

Keep the child zone signed and keep the attacker in strip mode. Change only the
parent's DS-publication setting in `.env`:

```dotenv
ATTACK_MODE=strip
INSERT_CHILD_DS=false
```

Rebuild the DNSSEC chain from fresh handoff files. Recreating the nameserver
containers is important: it starts `tld-ns` from its original zone file
without a DS left by Run A.

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
```

Wait for `domain-ns`, `tld-ns`, `root-ns`, and `resolver` startup to complete.
Check the logs:

```powershell
docker logs domain-ns
docker logs tld-ns
docker logs root-ns
docker logs resolver
```

`domain-ns` should still sign `example.com` and publish its DS, while `tld-ns`
should log that it is withholding that DS. The root-to-`.com` trust chain
remains intact.

Confirm the parent returns a signed no-DS result, then test the forged answer:

```powershell
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' DS example.com +dnssec +noall +comments +answer +authority
docker exec client dig '@172.16.2.10' example.com A +dnssec +noall +comments +answer +stats
docker exec client delv -a /pki/root-anchor.conf '@172.16.2.10' example.com A +rtrace
docker exec client curl -i --max-time 10 http://example.com/
```

The DS lookup should have no DS answer and should retain the signed denial proof
from `com`. The A lookup should return `172.16.1.30` (normally without the AD
flag), and the HTTP request should display the ROGUE server marker. The child
still has DNSKEY/RRSIG records in its signed zone; the error is that the
operator never published its DS in the parent, so the root-anchored resolver
has no authenticated link that makes the child secure.

Capture Run B in another terminal while running the checks:

```powershell
docker exec attacker tcpdump -ni eth0 -w /tmp/run-b.pcap udp port 53
```

Stop it with Ctrl+C, then save the capture and logs:

```powershell
docker cp attacker:/tmp/run-b.pcap .\run-b.pcap
docker logs --since 10m attacker | Tee-Object .\run-b-attacker.log
docker logs --since 10m resolver | Tee-Object .\run-b-resolver.log
docker logs --since 10m core-router | Tee-Object .\run-b-core-router.log
```

## 4.4 Report checklist

For each run, include:

- The `dig` and `delv` output, HTTP result, attacker/resolver/router logs, and
  the packet capture.
- Run A's failure: stripping authenticated records cannot turn a secure
  delegation into an authenticated insecure one. The resolver relies on the
  signed parent's DS and requires valid DNSSEC denial data before accepting a
  no-DS state.
- Run B's success: the only deployment change is withholding `example.com`'s
  DS from the `com` zone. That operator mistake leaves a signed but insecure
  child, so the resolver accepts the forged A after its signatures are removed.
- The contrast: downgrade resistance comes from the authenticated chain of
  trust, specifically the parent's signed DS (or signed proof of its absence),
  not merely from signatures existing in the child zone. The mistake that
  forfeits it is signing the child but failing to publish its DS in the parent.
