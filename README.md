# CloudFront IP Scanner

Finds CloudFront edge IPs that accept TLS connections with `SNI=127.0.0.1` and are reachable
from censored networks. Run this script from inside the censored region — IPs that time out
are not routed there and would be useless anyway.

No external dependencies — Python standard library only.

## Usage

```bash
# Fast scan — best starting point (~488k IPs, ~5-15 min)
python scanner.py --fast

# Full priority scan — thorough, finds more IPs (~2.3M IPs, ~20-60 min)
python scanner.py --priority

# Verify IPs work end-to-end with your CloudFront distribution
python scanner.py --fast --ws-host YOUR-DIST.cloudfront.net --ws-path /your/path

# Generate ready-to-use vless:// configs
python scanner.py --fast --vless --uuid YOUR-UUID --ws-host YOUR-DIST.cloudfront.net

# Scan a specific range
python scanner.py --range 13.249.0.0/16

# Increase timeout for slow/censored connections (recommended)
python scanner.py --fast --timeout 6
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--fast` | Scan highest-density ranges (~488k IPs) | - |
| `--priority` | Scan all known-good ranges (~2.3M IPs) | - |
| `--all` | Scan all CloudFront ranges from AWS API | - |
| `--range CIDR` | Scan a specific CIDR range exhaustively | - |
| `--file FILE` | Scan IPs from a file (one per line) | - |
| `--sni HOST` | SNI for TLS handshake | `127.0.0.1` |
| `--ws-host HOST` | Host header for stage-2 WS verification | disabled |
| `--ws-path PATH` | WebSocket path for stage-2 verification | `/api/v1/chat` |
| `--workers N` | Concurrent threads | `200` |
| `--timeout N` | Per-IP timeout in seconds | `3.0` |
| `--vless` | Generate vless:// URIs for found IPs | - |
| `--uuid UUID` | UUID to embed in vless configs | - |
| `--output FILE` | Output file for working IPs | `working_ips.txt` |

## How it scans

Every range is expanded into `/24` subnets and each subnet is scanned exhaustively —
no sampling. This guarantees every IP is checked regardless of range size.

**Stage 1 — TLS handshake** (`SNI=127.0.0.1`): IPs that complete the handshake pass.
Results shown as `TLS-only`. These are valid to use without stage 2.

**Stage 2 — WebSocket upgrade** (only when `--ws-host` is set): sends a real WS upgrade
with your CloudFront domain as the `Host` header.
- `101 WS` — confirmed end-to-end working
- `HTTP 421` — not usable (strict Host matching)

## Output files

- `working_ips.txt` — one IP per line
- `working_ips_vless.txt` — vless:// URIs (with `--vless` flag)

## Bundled IP ranges

`cf_ranges.json` is bundled and used as a fallback if the AWS API is unreachable.
Update it periodically from an uncensored connection:

```bash
python -c "
import json, urllib.request
with urllib.request.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json') as r:
    data = json.loads(r.read())
cf = sorted(set(p['ip_prefix'] for p in data['prefixes'] if p['service'] == 'CLOUDFRONT'))
with open('cf_ranges.json', 'w') as f:
    json.dump({'updated': data['createDate'], 'ranges': cf}, f, indent=2)
print(len(cf), 'ranges saved')
"
```

## VLESS clients

| Platform | Apps |
|----------|------|
| iOS | Shadowrocket, V2Box, Streisand |
| Android | V2rayNG, NekoBox, Matsuri |
| Windows | V2rayN, Nekoray, Qv2ray |
| macOS | V2rayU, Qv2ray |
| Linux | Nekoray, Qv2ray |

## How It Works

1. Fetches CloudFront IP ranges from AWS API
2. Attempts TLS handshake with `SNI=127.0.0.1`
3. IPs that accept the connection are saved
4. Optionally generates VLESS proxy configs

## Why SNI 127.0.0.1?

CloudFront edge servers accept TLS connections with invalid SNI values like `127.0.0.1`. The actual routing happens via the `Host` header in the WebSocket upgrade request, allowing CDN-based proxy setups.

## Disclaimer

For educational purposes and CTF challenges only. Use responsibly.

## License

MIT
