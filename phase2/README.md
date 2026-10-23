# Phase 2 - DNS Interception Lab

Phase 2 carries over the Phase 1 DNS hierarchy and adds a rogue web server
(`172.16.1.30`) and an attacker container (`172.16.2.100`) on the resolver
subnet. The core router routes resolver-bound replies through the attacker.

## Current implementation status

The interceptor currently has two modes, selected by `INTERCEPT_MODE` in
`.env`:

| Setting | Attacker mode | Behavior |
| --- | --- | --- |
| `INTERCEPT_MODE=false` | `normal` | Captures and relays DNS packets without modifying their contents. |
| `INTERCEPT_MODE=true` | `intercept` | Captures and logs DNS packets, but does not relay or modify them. |

**Response forgery and resolver cache poisoning are not implemented.** In
`intercept` mode, replies routed through the attacker are not forwarded, so
queries that need an upstream response can time out. A cached resolver answer
may still be returned. Do not expect `example.com` to resolve to the rogue
server in either current mode.

The resolver and authoritative name servers use their Phase 1 configuration.
The Phase 2 attacker route is configured on `core-router`; inspect it with:

```powershell
docker exec core-router ip route get 172.16.2.10
```

When the diversion is active, the route output should show `via 172.16.2.100`.

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

For transparent relay mode:

```powershell
docker compose up -d --build --force-recreate attacker
docker logs attacker
```

Set `INTERCEPT_MODE=true` in `.env` and run the same commands to select
monitor-only mode. With the core-router diversion active, DNS queries may time
out in this mode because the interceptor does not relay packets.

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
