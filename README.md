# CloudFront IP Scanner

A tool for finding CloudFront edge IPs that accept TLS connections with SNI=127.0.0.1. Useful for CDN-based proxy configurations.

## Features

- Fetches official CloudFront IP ranges from AWS
- Multi-threaded scanning (100+ concurrent connections)
- Generates ready-to-use VLESS configs
- Supports custom SNI values

## Installation
```bash
git clone https://github.com/useruserdev/cloudfront-scanner.git
cd cloudfront-scanner
```

No dependencies required — uses only Python standard library.

## Usage
```bash
# Quick scan (samples from all CloudFront ranges)
python3 scanner.py --quick

# Scan specific CIDR range
python3 scanner.py --range 3.160.144.0/22

# Generate VLESS configs
python3 scanner.py --quick --vless

# Custom SNI
python3 scanner.py --quick --sni localhost

# More workers for faster scanning
python3 scanner.py --range 3.160.0.0/16 --workers 200
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--quick` | Quick scan (sample IPs from all ranges) | - |
| `--range CIDR` | Scan specific CIDR range | - |
| `--file FILE` | Scan IPs from file | - |
| `--sni HOST` | SNI for TLS handshake | 127.0.0.1 |
| `--workers N` | Concurrent threads | 100 |
| `--samples N` | IPs per range in quick mode | 30 |
| `--vless` | Generate VLESS URLs | - |
| `--output FILE` | Output file | working_ips.txt |
| `--host HOST` | WebSocket host for VLESS | - |

## Output

- `working_ips.txt` — List of working IPs
- `working_ips_vless.txt` — Ready VLESS configs (with `--vless` flag)

## VLESS Clients

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
