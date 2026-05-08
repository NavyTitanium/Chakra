# chakra

**Offensive recon harvester for Next.js / React single-page applications.**

Chakra recursively pulls every JavaScript chunk from a target, unpacks webpack bundles, recovers source maps, scans for secrets and leaked credentials, maps the full API surface, detects inlined environment variables, and discovers subdomains all in a single run with no browser required.

---

## What it does

| Module | Description |
|---|---|
| **Chunk harvesting** | Fetches all JS assets referenced in HTML, build manifests, and webpack chunk registries. BFS-recursive: follows every reference found in each downloaded file. |
| **Source map recovery** | Detects `sourceMappingURL` references (external and inline base64). Reconstructs the original pre-minification TypeScript/JSX source tree under `sourcemaps/`. |
| **Secret scanning** | 42 patterns covering AWS, GCP, Firebase, Stripe, Twilio, GitHub, JWT, Clerk, Supabase, database URLs, OpenAI, Sentry, Datadog, internal IPs, hardcoded passwords, and more. Results written to `_secrets.json` with file path, line number, and context. |
| **Route extraction** | Identifies API endpoints, `fetch()`/`axios` calls, GraphQL paths, tRPC routes, and parametric REST paths. Outputs `_routes.txt` (one path per line, ready for ffuf/nuclei) and `_routes.json`. |
| **Env var leakage** | Finds `process.env.*` references with inlined values: variables that were accidentally bundled into the client build. Leaked values flagged separately in `_env_vars.json`. |
| **`__NEXT_DATA__` harvesting** | Extracts the SSR props blob from Next.js pages, recovers the build ID, and probes `/_next/data/<buildId>/<route>.json` endpoints for server-side data. Also captures React Server Component streaming payloads. |
| **Webpack chunk map** | Parses the runtime chunk registry (`{id:"hash"}` objects) to discover lazy-loaded chunks that are never referenced in HTML or build manifests, including hidden admin routes. |
| **Subdomain discovery** | Scans all downloaded content for hostnames matching the target's apex domain. Surfaces candidates like `api.target.com`, `app.target.com`, `admin.target.com`. |
| **Interactive expansion** | After the primary harvest, prompts you to launch full recursive scans against any discovered subdomains, each in its own output directory. |

---

## Installation

```bash
git clone https://github.com/yourhandle/chakra
cd chakra
pip install requests jsbeautifier brotlicffi
```

Python 3.10+ required.

---

## Usage

```bash
# Basic run, output saved to ./target.com/
python3 chakra.py https://target.com

# With extra seed pages (discovers route-specific chunks)
python3 chakra.py https://target.com -p /dashboard -p /admin -p /settings

# Custom output dir, 16 threads, verbose
python3 chakra.py https://target.com -o ./loot -t 16 -v

# Custom User-Agent
python3 chakra.py https://target.com -ua "Mozilla/5.0 (compatible; Googlebot/2.1)"

# Skip beautification for speed (large apps)
python3 chakra.py https://target.com --no-beautify

# Skip secret scanning and source map recovery
python3 chakra.py https://target.com --no-scan --no-sourcemaps

# Throttle requests (avoid rate limiting)
python3 chakra.py https://target.com --delay 0.5
```

### All options

```
positional arguments:
  target                Target URL (e.g. https://target.com/)

options:
  -o, --output DIR      Output directory (default: ./<apex-domain>)
  -t, --threads N       Concurrent download threads (default: 8)
  -d, --depth N         Maximum BFS recursion depth (default: 10)
  -p, --page PATH       Extra seed page path — repeatable (-p /admin -p /dashboard)
  --timeout SEC         HTTP read timeout per attempt (default: 30)
  --connect-timeout SEC TCP+TLS connect timeout (default: 10)
  --retries N           Retry attempts on timeout/5xx with exponential back-off (default: 3)
  -ua, --user-agent UA  User-Agent string
  --no-beautify         Skip JS beautification, save raw minified files
  --no-scan             Skip secret and env-var scanning
  --no-sourcemaps       Skip source map recovery
  --delay SEC           Per-request throttle delay in seconds
  -v, --verbose         DEBUG-level logging
```

---

## Output structure

```
target.com/
├── index.html                          # Root page HTML
├── _next/
│   └── static/
│       └── chunks/
│           ├── main-abc123.js          # Beautified JS chunks
│           ├── framework-def456.js
│           └── ...
├── sourcemaps/
│   └── main-abc123/
│       └── src/
│           ├── components/
│           │   └── Dashboard.tsx       # Recovered original source
│           └── utils/
│               └── api.ts
├── _next_data.json                     # __NEXT_DATA__ SSR props blob
├── _rsc_payloads.txt                   # React Server Component payloads
├── _secrets.json                       # Secret findings with file + line context
├── _routes.json                        # API endpoints with source file references
├── _routes.txt                         # One endpoint per line (ffuf/nuclei ready)
├── _env_vars.json                      # process.env.* references, leaked values first
├── _subdomains.txt                     # Discovered subdomains, priority-sorted
└── _harvest_summary.json               # Run metadata and stats
```

---

## Example output

```
========================================================================
  HARVEST COMPLETE
  Elapsed      : 28.3s
  Fetched      : 27 URLs
  Saved        : 21 files
  Secrets      : 4 findings
  Routes       : 63 unique
  Env vars     : 12 (3 leaked)
  Src files    : 147 from source maps
  Subdomains   : 5 discovered
========================================================================

  ⚠  TOP FINDINGS (full list in _secrets.json):
    [Supabase URL]      https://xyzxyz.supabase.co         (main-abc123.js:16738)
    [JWT Token]         eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp...  (main-abc123.js:16738)
    [Stripe Test Key]   pk_test_51abc...                   (chunk-def456.js:4201)
    [Sentry DSN]        https://abc123@o999.ingest.sentry  (chunk-ghi789.js:891)

  🌐  SUBDOMAINS DISCOVERED (5 unique)
────────────────────────────────────────────────────────────────────────
  [ 1]  ★  api.target.com
  [ 2]  ★  app.target.com
  [ 3]  ★  admin.target.com
  [ 4]     cdn.target.com
  [ 5]     static.target.com

  Enter numbers to expand (e.g. 1,3,5), 'all', or ENTER to skip:
  > 1,3
```

---

## How it works

### Chunk discovery pipeline

Modern Next.js / React apps ship a minimal HTML shell that references a handful of entry chunks. Those chunks reference more chunks via webpack's async `import()` system and runtime chunk registries. Chakra walks this graph completely:

1. **HTML seed** — parses `<script src>` tags and `__NEXT_DATA__` from the root page and any extra `-p` pages
2. **Build manifest** — fetches `/_next/static/<buildId>/_buildManifest.js` which maps every page route to its required chunks
3. **Webpack chunk map** — parses `{id:"hash"}` runtime objects inside chunks to discover lazy-loaded assets never referenced in HTML
4. **Recursive BFS** — every downloaded JS file is scanned for further chunk references, up to `--depth`

### Source map recovery

When a JS file contains `//# sourceMappingURL=`, chakra fetches the `.map` file and reconstructs the original source tree from `sources[]` and `sourcesContent[]`. For apps that accidentally ship source maps to production, this recovers the full pre-build TypeScript/JSX with original filenames, directory structure, and comments — often more readable than the beautified bundle.

### Secret scanner

42 compiled regex patterns organized by category. Each finding records the label, matched value, file path, line number, and the surrounding line for context. Patterns include:

- **Cloud providers** — AWS access/secret keys, GCP API keys, Firebase credentials
- **Payment** — Stripe live and test keys (both `sk_` and `pk_`)
- **Auth platforms** — Clerk publishable/secret keys, Supabase anon keys and URLs, JWT tokens, Bearer tokens
- **Communication** — Twilio, Sendgrid, Mailgun, Slack tokens and webhooks
- **Observability** — Sentry DSNs, Datadog keys, New Relic keys
- **Databases** — Connection string URLs (PostgreSQL, MySQL, MongoDB, Redis), hardcoded passwords
- **Internal infrastructure** — RFC1918 IP ranges, `.internal`/`.corp`/`.lan`/`.intranet` hostnames in string context
- **AI/ML** — OpenAI keys (`sk-`), Anthropic keys (`sk-ant-`)
- **Analytics/CRM** — HubSpot, Segment, Intercom, Algolia, Pusher
- **Generic** — `secret`, `api_key`, `private_key`, `auth_token` patterns with adjacent values

The internal hostname pattern uses context-aware matching — only triggers when the hostname appears inside a string literal or URL, not on JS property access like `e.internal` or `result.internal`.

---

## Notes

- **Brotli support** — install `brotlicffi` for full compression support. Without it, chakra falls back to gzip/deflate only and drops `br` from `Accept-Encoding` to avoid receiving compressed content it cannot decode.
- **Beautification** — uses `jsbeautifier` with `unescape_strings=True`. Large apps (500KB+ chunks) can be slow to beautify; use `--no-beautify` if speed matters more than readability.
- **Rate limiting** — use `--delay` to throttle. CDN-hosted static assets rarely rate-limit, but origin servers behind WAFs may.
- **Source maps in production** — surprisingly common. Some CI pipelines upload them accidentally; some developers leave them intentionally for debugging. When present they hand you the complete pre-build source including TypeScript types, comments, and TODO notes.
- **Subdomain expansion** — each subdomain harvest is a fully independent run with identical settings to the primary. Discovered subdomains from expansion runs are surfaced in their own `_subdomains.txt`.

---

## Legal

Use only against targets you are authorized to test. The authors accept no liability for misuse. This tool is intended for authorized penetration testing, bug bounty research, and security assessments.

---

## License

MIT
