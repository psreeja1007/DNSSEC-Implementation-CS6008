# Phase 5 - DNSSEC Zone Walking

Phase 5 is an independent copy of the Phase 4 lab. It reuses the signed
root -> `.com` -> `example.com` hierarchy and the validating resolver. The
child zone contains five extra internal hostnames. In the first run it uses
NSEC denial, allowing an observer to follow the signed owner-name chain. In
the second run it uses NSEC3, which replaces cleartext next-owner names with
hashes and stops the same query-only walk.

The Compose project is `cs6008-phase5`, and containers have no fixed names, so
Phase 5 can run alongside other phases without reusing their containers or
networks. Run commands below from `phase5/`.

## 5.1 Deploy with walkable NSEC

The default `.env` selects the walkable configuration:

```dotenv
ATTACK_MODE=normal
INSERT_CHILD_DS=true
DENIAL_MODE=nsec
```

Start the lab with fresh DNSSEC handoff files:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
```

Wait for the signer and trust chain to finish:

```powershell
docker compose logs domain-ns
docker compose logs tld-ns
docker compose logs root-ns
docker compose logs resolver
```

`domain-ns` should report `denial mode: nsec`; the child DS should be inserted
into `com`, and the `com` DS into the root zone.

The zone contains these owner names: `example.com`, `www`, `domain-ns`,
`admin`, `dev`, `git`, `mail`, and `vpn`. The five internal labels are only in
the zone file and are not published elsewhere as hints.

## 5.2 Verify authenticated denial

Ask for an absent name and inspect the authenticated NSEC proof:

```powershell
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Expect `NXDOMAIN`, the `ad` flag, and an NSEC plus RRSIG in the authority
section. `delv` should report that the denial was fully validated.

## 5.3 Attack - walk the NSEC chain

NSEC records are ordered links: each record exposes its cleartext owner and
the next owner name. Start with only the known apex. Query a type that does not
exist at each discovered owner (`TXT` here), read the next owner from the NSEC
RDATA, and repeat until the chain returns to `example.com.`:

```powershell
docker compose exec client dig '@172.16.2.10' example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' admin.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' dev.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' domain-ns.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' git.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' mail.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' vpn.example.com TXT +dnssec +noall +comments +answer +authority
docker compose exec client dig '@172.16.2.10' www.example.com TXT +dnssec +noall +comments +answer +authority
```

Use the NSEC next-owner field to decide the next query; the order shown above
is not required and is not a wordlist. The proof's NSEC owner also identifies
the current owner. Stop as soon as the next-owner field returns to the apex.
There are eight owner names including the known apex, so the complete walk
uses eight queries (within the limit of names + 2). Do not use AXFR or guess
candidate labels.

The recovered set is:

```text
example.com.
admin.example.com.
dev.example.com.
git.example.com.
mail.example.com.
vpn.example.com.
www.example.com.
domain-ns.example.com.
```

## 5.4 Mitigation - reconfigure the signer for NSEC3

Change only the denial mode in `.env`:

```dotenv
DENIAL_MODE=nsec3
NSEC3_SALT=a1b2c3d4
```

`domain-ns/entrypoint.sh` now passes the BIND `dnssec-signzone -3 <salt>`
option when `DENIAL_MODE=nsec3`; `-3` selects NSEC3. Rebuild the signed
hierarchy from clean handoff files so the child is re-signed and all DS
records and trust anchors correspond to the current keys:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
docker compose logs domain-ns
```

The signer should log `denial mode: nsec3`. Verify authenticated denial still
works:

```powershell
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Expect `NXDOMAIN`, `ad`, and signed NSEC3 proof records; `delv` should still
report a fully validated denial. Then repeat the walk from the apex:

```powershell
docker compose exec client dig '@172.16.2.10' example.com TXT +dnssec +noall +comments +answer +authority
```

The authority section now contains NSEC3 hashes, not a cleartext next-owner
name. There is no next hostname to use as the following query, so this
query-only walk discovers none of the five hidden labels. Unlike NSEC, NSEC3
does not provide a direct enumerable chain of plaintext owners. It is not
absolute confidentiality: an attacker with likely candidate names can
perform offline dictionary guesses against the hashes, especially when names
are predictable.

## 5.5 Report

- List the eight owner names recovered, the starting apex query, and the
  sequence of NSEC next-owner values and queries. Include the signed denial
  output and resolver validation evidence.
- The walk is enabled by the signer's default NSEC behavior (no NSEC3 option).
  A signed NSEC record authenticates a cleartext link from one existing owner
  to the next, making repeated queries a zone walk. Plain DNS does not include
  those links in its negative answers.
- The mitigation is NSEC3, selected by the exact
  `dnssec-signzone -3 <salt>` signing option. It replaces cleartext owner
  links with hashes while preserving authenticated nonexistence proofs.
- The tradeoff is extra hash computation and larger NSEC3 records during zone
  signing and validation. NSEC3 prevents the simple walk, but does not hide
  names that can be guessed with offline dictionary attacks; the salt must be
  configured and maintained as part of zone-signing operations.
