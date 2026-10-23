# Phase 2 - DNS Interception Lab

Phase 2 carries over the Phase 1 DNS hierarchy and adds a rogue web server
(`172.16.1.30`) and an attacker container (`172.16.2.100`) on the resolver
subnet. For the normal DNS path, resolver-bound replies are not diverted
through the attacker.

## Current implementation status

The interceptor currently has two modes, selected by `INTERCEPT_MODE` in
`.env`:

| Setting | Attacker mode | Behavior |
| --- | --- | --- |
| `INTERCEPT_MODE=false` | `normal` | Uses the normal DNS route; the attacker is not in the resolver reply path. |
| `INTERCEPT_MODE=true` | `intercept` | Selects the experimental interceptor branch; it does not change the core-router route. |

**Response forgery and resolver cache poisoning are not implemented.** In
The core router does not install a route through the attacker. This keeps
normal recursive lookups independent of the interceptor. The experimental
interceptor branch is not part of the verified normal DNS path. Do not expect
`example.com` to resolve to the rogue server when using normal mode.

The resolver and authoritative name servers use their Phase 1 configuration.
Check the resolver route on `core-router`:

```powershell
docker exec core-router ip route get 172.16.2.10
```

For normal DNS, the output should not show `via 172.16.2.100`.

## Deploy

Run the following commands from `phase2/`. Stop Phase 1 first if it is running
with colliding container names.

```powershell
docker compose build
docker compose up -d
docker compose ps
```

Check the selected mode and startup diagnostics:

```powershell
docker logs attacker
```

## Select a mode

Edit `INTERCEPT_MODE` in `.env`, then recreate the attacker container:

```dotenv
INTERCEPT_MODE=false
```

For normal DNS mode:

```powershell
docker compose up -d --build --force-recreate attacker
docker logs attacker
```

Set `INTERCEPT_MODE=true` in `.env` and recreate the attacker to select
monitor-only mode. The core router still does not divert resolver replies, so
normal DNS remains available.

## Check DNS and web connectivity

Query the resolver directly. In PowerShell, quote the `@server` argument:

```powershell
docker exec resolver rndc flush
docker exec client dig '@172.16.2.10' example.com +noall +answer +stats
docker exec client dig '@172.16.2.10' www.example.com +noall +answer +stats
```

With a normal Phase 1 answer, `example.com` resolves to `172.16.1.20`.
`www.example.com` also resolves to `172.16.1.20`.

To check that the rogue web server is reachable independently of DNS:

```powershell
docker exec client curl -s --max-time 10 http://172.16.1.30/
```

That direct request tests web connectivity only; it does not change name
resolution.
