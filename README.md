# subrecon

A subdomain reconnaissance tool that combines `subfinder`, `assetfinder`, and `httpx` into a single command — passive subdomain enumeration, deduplication, and live-host probing in one pipeline.

Written in Go. Installs itself and its dependencies with one command.

## What it does

1. Runs `subfinder` and `assetfinder` against a target domain (two different passive data sources, more coverage than either alone)
2. Merges and deduplicates the results
3. Probes every subdomain with `httpx` to find which are actually live, returning status code, page title, and detected tech stack

## Installation

Requires [Go](https://go.dev/dl/) installed.

```bash
go install github.com/letxworld/subrecon@latest
```

That's it. `subrecon` will automatically check for `subfinder`, `assetfinder`, and `httpx` on first run and install any that are missing — no manual setup of underlying tools required.

## Usage

```bash
subrecon -d target.com
```

**Flags:**

| Flag | Description | Default |
|---|---|---|
| `-d` | Target domain (required) | — |
| `-s` | Save results to disk under `results/<domain>/` | off |
| `-o` | Custom output file path for live hosts | — |
| `-rl` | Max requests/second for httpx (rate limit) | 150 |
| `-timeout` | Per-request timeout in seconds | 10 |

**Examples:**

```bash
# Quick scan, print results to terminal only
subrecon -d target.com

# Save results to results/target.com/
subrecon -d target.com -s

# Save live hosts to a custom file
subrecon -d target.com -o my_scan.txt

# Slow down requests for a rate-limited target
subrecon -d target.com -rl 20 -timeout 15
```

By default, nothing is written to disk — results print to your terminal only. Use `-s` or `-o` to persist results.

## ⚠️ Legal / Scope

**Only run this tool against domains you own, or where you have explicit written authorization to test** (e.g., an active bug bounty program's in-scope assets, or your own infrastructure).

Passive subdomain enumeration queries public data sources and is generally low-risk on its own, but:
- Many organizations' bug bounty programs explicitly define in-scope vs out-of-scope assets — always check scope before testing anything you find, including subdomains
- Running this against a target with no authorization at all may violate computer misuse laws depending on jurisdiction, regardless of how "passive" the technique feels

This tool is built for authorized security research and bug bounty work. The author is not responsible for misuse.

## How it's built

- Written in Go, single binary, no runtime dependencies beyond the three tools it wraps
- Auto-installs `subfinder`, `assetfinder`, `httpx` via `go install` on first run if missing
- Rate-limit and timeout flags are forwarded directly to the underlying tools rather than reimplemented — simpler and more reliable than custom concurrency logic

## Author

Dipesh Pokhrel — [LinkedIn](https://www.linkedin.com/in/dipesh-pokhrel-2a6002375) | [GitHub](https://github.com/letxworld)