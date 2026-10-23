# Phase 5 - DNSSEC Zone Walking

Phase 5 reuses the Phase 3 signed root -> `.com` -> `example.com` hierarchy
and validating resolver. The Phase 3 deployment is otherwise unchanged: the
resolver trusts the root KSK and validates the signed chain. Phase 5 adds
undisclosed owner names to `example.com` and makes the child signer selectable
between NSEC and NSEC3.

The Compose project is `cs6008-phase5`; fixed container names have been
removed so the Phase 3 lab can coexist. Run commands from `phase5/`.

## 5.1 Deploy the signed Phase 3 hierarchy

The `.env` defaults preserve the normal Phase 3 DNS path and choose walkable
NSEC denial:

```dotenv
INTERCEPT_MODE=false
DENIAL_MODE=nsec
```

Build and start the independent stack with fresh DS/trust-anchor handoff files:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
docker compose logs domain-ns
docker compose logs tld-ns
docker compose logs root-ns
docker compose logs resolver
```

The domain signer should report `denial mode: nsec`. The child DS should be
inserted into `com`, the `com` DS into the root zone, and the resolver should
install the root KSK trust anchor.

In addition to the existing apex, `www`, and `domain-ns` names, the zone
contains five internal labels that are not advertised elsewhere:

```text
admin.example.com.
dev.example.com.
git.example.com.
mail.example.com.
vpn.example.com.
```

## 5.2 Verify authenticated denial

Ask for an absent name and inspect its signed denial:

```powershell
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Expect `NXDOMAIN`, the `ad` flag, and NSEC plus RRSIG records in the authority
section. `delv` should report a fully validated negative answer.

## 5.3 Walk the NSEC chain

An NSEC record exposes the current owner name and the next owner name in
canonical DNS order. Starting only with the known apex, query a nonexistent
type (`TXT`) at each owner and follow the NSEC next-owner field. The NSEC RDATA
also gives the current owner:

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

Follow the response, not this listing, to choose the next query. The chain
observed in this zone is:

```text
example.com -> admin.example.com -> dev.example.com
-> domain-ns.example.com -> git.example.com -> mail.example.com
-> vpn.example.com -> www.example.com -> example.com
```

Stop once the next-owner field returns to `example.com`. This recovers all
eight owner names in eight queries, within the `number of names + 2` limit.
The five previously undisclosed names are `admin`, `dev`, `git`, `mail`, and
`vpn`. This procedure uses only the authenticated NSEC responses; do not use
AXFR or a candidate-name wordlist.

## 5.4 Reconfigure denial with NSEC3

Change the denial mode in `.env`:

```dotenv
DENIAL_MODE=nsec3
NSEC3_SALT=a1b2c3d4
```

The Phase 3 signer still generates the same DNSSEC keys and publishes the
child DS in the same way. The Phase 5-only change passes BIND's
`dnssec-signzone -3 <salt>` option for the `example.com` child, selecting
NSEC3. Re-sign the chain from fresh handoff files:

```powershell
docker compose down
Remove-Item .\common\pki\example.com.ds, .\common\pki\com.ds, .\common\pki\root.key, .\common\pki\root-anchor.conf -ErrorAction SilentlyContinue
docker compose up -d --build
docker compose ps
docker compose logs domain-ns
```

The domain signer should report `denial mode: nsec3`. Check that a nonexistent
name still receives authenticated denial:

```powershell
docker compose exec resolver rndc flush
docker compose exec client dig '@172.16.2.10' not-real.example.com A +dnssec +noall +comments +answer +authority
docker compose exec client delv -a /pki/root-anchor.conf '@172.16.2.10' not-real.example.com A +rtrace
```

Expect `NXDOMAIN`, `ad`, NSEC3/RRSIG records, and fully validated denial.
Repeat a query starting from the known apex:

```powershell
docker compose exec client dig '@172.16.2.10' example.com TXT +dnssec +noall +comments +answer +authority
```

The proof contains hashed owner names and hashed next-owner values rather than
the cleartext NSEC link. The same procedure therefore does not reveal a next
hostname, and the walk recovers none of the five labels. NSEC3 is not absolute
confidentiality: predictable names may still be tested using offline
dictionary guesses against the hashes.

## 5.5 Report

- Include the starting apex query, each NSEC owner/next-owner pair, the eight
  recovered names, and the validated NXDOMAIN evidence.
- Default NSEC signing makes the walk possible. Signed denial has to cover
  arbitrary names not known when signatures are generated; NSEC does this
  with a signed, cleartext link between existing owners. Ordinary DNS answers
  do not publish that chain.
- NSEC3 (`dnssec-signzone -3 <salt>`) replaces that link with hashes while
  preserving authenticated denial.
- The operator cost is additional hashing during signing and validation,
  larger denial records, and salt lifecycle management. NSEC3 obstructs a
  straightforward zone walk, but likely/predictable names can still be
  recovered by dictionary guessing.
