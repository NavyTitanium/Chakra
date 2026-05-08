#!/usr/bin/env python3
"""
nextjs_harvester.py — Next.js / React SPA offensive recon harvester

Recursively discovers, downloads, and beautifies all JS chunks from a target,
then performs post-processing analysis:
  • Source map recovery      — reconstructs original pre-minification source tree
  • Secret scanning          — flags API keys, tokens, credentials, internal hosts
  • Route/endpoint extraction — builds a full API surface inventory
  • __NEXT_DATA__ harvesting  — extracts SSR props, RSC payloads, data routes
  • Env var leakage detection — finds process.env.* values inlined at build time
  • Webpack chunk map         — parses runtime chunk registry for hidden routes

Usage:
    python3 nextjs_harvester.py https://target.com
    python3 nextjs_harvester.py https://target.com -o ./loot -t 16 -p /dashboard -p /admin
    python3 nextjs_harvester.py https://target.com --no-beautify --no-scan -v
"""

import argparse
import base64
import hashlib
import json
import logging
import gzip
import re
import sys
import time
import zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from urllib.parse import urljoin, urlparse

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependencies
# ─────────────────────────────────────────────────────────────────────────────
try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    try:
        import brotlicffi as brotli
        BROTLI_AVAILABLE = True
    except ImportError:
        BROTLI_AVAILABLE = False

try:
    import jsbeautifier
    JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    JSBEAUTIFIER_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_UA = ( "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36" )
DEFAULT_THREADS    = 4
DEFAULT_DEPTH      = 10
DEFAULT_TIMEOUT    = 30
DEFAULT_CONNECT_TO = 10
DEFAULT_RETRIES    = 3

# ─────────────────────────────────────────────────────────────────────────────
# Secret scanning patterns  (label, compiled_regex)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",         re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])')),
    ("AWS Secret Key",         re.compile(r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\s:=]+([A-Za-z0-9/+=]{40})')),
    ("GCP API Key",            re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Firebase URL",           re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')),
    ("Firebase API Key",       re.compile(r'(?i)firebase[^"\']{0,30}["\']([A-Za-z0-9_\-]{30,50})["\']')),
    ("Stripe Live Key",        re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Pub Live Key",    re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Test Key",        re.compile(r'(?:sk|pk)_test_[0-9a-zA-Z]{24,}')),
    ("Twilio SID",             re.compile(r'AC[a-f0-9]{32}')),
    ("Twilio Auth Token",      re.compile(r'(?i)twilio[^"\']{0,20}["\']([a-f0-9]{32})["\']')),
    ("Sendgrid Key",           re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}')),
    ("Mailgun Key",            re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Slack Token",            re.compile(r'xox[baprs]-[0-9A-Za-z\-]+')),
    ("Slack Webhook",          re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+')),
    ("GitHub Token",           re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}')),
    ("JWT Token",              re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("Bearer Token",           re.compile(r'(?i)bearer\s+([A-Za-z0-9_\-\.=+/]{20,})')),
    ("Basic Auth (b64)",       re.compile(r'(?i)basic\s+([A-Za-z0-9+/=]{20,})')),
    ("Clerk Publishable Key",  re.compile(r'pk_(?:test|live)_[A-Za-z0-9]{20,}')),
    ("Clerk Secret Key",       re.compile(r'sk_(?:test|live)_[A-Za-z0-9]{20,}')),
    ("Supabase Anon Key",      re.compile(r'(?i)supabase[^"\']{0,30}["\']([A-Za-z0-9_\-\.]{100,})["\']')),
    ("Supabase URL",           re.compile(r'https://[a-z0-9]+\.supabase\.co')),
    ("Database URL",           re.compile(r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s\'"<>]+')),
    ("Generic DB Password",    re.compile(r'(?i)(?:db_pass|database_password|db_password)["\s:=]+["\']([^"\']{8,})["\']')),
    ("Google OAuth Client",    re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com')),
    ("Generic Secret",         re.compile(r'(?i)(?:secret|api[_\-]?key|private[_\-]?key|auth[_\-]?token|access[_\-]?token)["\s:=]+["\']([A-Za-z0-9_\-\.=+/]{16,})["\']')),
    ("Internal IPv4",          re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)')),
    ("Internal Hostname",      re.compile(
        # Only match hostnames in string/URL context (preceded by quote, slash, space, =, or ().
        # Eliminates JS property access (e.internal, result.internal) since those appear
        # after operators/dots, never after string delimiters.
        # Labels min 2 chars covers real infra names (db, s3, lb, mq) while blocking
        # single-char JS identifiers (e.internal, x.local).
        r'(?:^|(?<=["\'\s`=(,/]))'                      # preceded by string/URL delimiter
        r'(?:https?://)?'                                # optional scheme
        r'([a-z0-9][a-z0-9\-]{1,63}'                    # first label ≥ 2 chars total
        r'(?:\.[a-z0-9][a-z0-9\-]{1,63}){0,3}'          # up to 3 more labels, each ≥ 2 chars
        r'\.(?:internal|local|intranet|corp\.internal|corp|lan|prod\.internal|staging))'
        r'(?=[:/\s"\'`<>(,\])]|$)',                      # end at URL/string delimiter
        re.IGNORECASE | re.MULTILINE,
    )),
    ("Hardcoded Password",     re.compile(r'(?i)password\s*[=:]\s*["\']([^"\']{8,})["\']')),
    ("Mapbox Token",           re.compile(r'pk\.eyJ1[A-Za-z0-9_\-\.]+')),
    ("Algolia App ID",         re.compile(r'(?i)algolia[^"\']{0,20}appid[^"\']{0,10}["\']([A-Z0-9]{10})["\']')),
    ("Algolia API Key",        re.compile(r'(?i)algolia[^"\']{0,20}(?:api|admin)[_\-]?key[^"\']{0,10}["\']([a-f0-9]{32})["\']')),
    ("OpenAI Key",             re.compile(r'sk-[A-Za-z0-9]{20,}')),
    ("Anthropic Key",          re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}')),
    ("Intercom Key",           re.compile(r'(?i)intercom[^"\']{0,20}["\']([A-Za-z0-9_\-]{20,})["\']')),
    ("Segment Write Key",      re.compile(r'(?i)segment[^"\']{0,20}write[_\-]?key[^"\']{0,10}["\']([A-Za-z0-9]{20,})["\']')),
    ("HubSpot Key",            re.compile(r'(?i)hubspot[^"\']{0,20}["\']([a-f0-9\-]{36})["\']')),
    ("Sentry DSN",             re.compile(r'https://[a-f0-9]{32}@(?:o\d+\.ingest\.)?sentry\.io/\d+')),
    ("New Relic Key",          re.compile(r'(?i)newrelic[^"\']{0,20}["\']([A-Za-z0-9]{40,})["\']')),
    ("Datadog Key",            re.compile(r'(?i)datadog[^"\']{0,20}["\']([a-f0-9]{32})["\']')),
    ("Pusher Key",             re.compile(r'(?i)pusher[^"\']{0,20}["\']([a-f0-9]{20,})["\']')),
    ("process.env leak",       re.compile(r'process\.env\.([A-Z_]{4,})\s*(?:=\s*["\']([^"\']{4,})["\']|\|\|)')),
]

# ─────────────────────────────────────────────────────────────────────────────
# Route extraction patterns
# ─────────────────────────────────────────────────────────────────────────────
ROUTE_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*["`\']([/][^"`\'\s)]{2,})["`\']'),
    re.compile(r'["`\'](/api/[a-zA-Z0-9_/\-\[\]{}:?&=.]{2,})["`\']'),
    re.compile(r'["`\']((?:/v\d+)?/[a-z][a-zA-Z0-9_/\-]{3,}(?:\?[^"`\']{0,60})?)["`\']'),
    re.compile(r'(?:pathname|route|path)\s*(?:===?|:)\s*["`\']([/][^"`\']{2,})["`\']'),
    re.compile(r'["`\']((?:https?://[^/]+)?/graphql[^"`\']*)["`\']'),
    re.compile(r'["`\'](/trpc/[a-zA-Z0-9_.]{2,})["`\']'),
    re.compile(r'["`\']([/][a-z][a-z0-9_\-/]*(?:/\{[^}]+\})+[^"`\']*)["`\']'),
]

ROUTE_NOISE_RE = re.compile(
    r'^(?:/_next/|/static/|/favicon|/icon|/apple-touch|/robots|/sitemap'
    r'|/manifest\.json|/__next|/__webpack|/node_modules|\.[a-z]{2,4}$)',
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Webpack chunk map  {id:"hash", ...}
# ─────────────────────────────────────────────────────────────────────────────
WEBPACK_CHUNK_MAP_RE   = re.compile(r'\{(?:\s*\d+\s*:\s*["\'][a-f0-9]{8,}["\'],?\s*){3,}\}')
WEBPACK_CHUNK_ENTRY_RE = re.compile(r'(\d+)\s*:\s*["\']([a-f0-9]{8,})["\']')

# ─────────────────────────────────────────────────────────────────────────────
# Source maps
# ─────────────────────────────────────────────────────────────────────────────
SOURCEMAP_URL_RE    = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)', re.MULTILINE)
INLINE_SOURCEMAP_RE = re.compile(
    r'//[#@]\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)'
)

BUILD_MANIFEST_RE = re.compile(r'/_next/static/([A-Za-z0-9_\-]+)/_buildManifest\.js')

# ─────────────────────────────────────────────────────────────────────────────
# Env var leakage
# ─────────────────────────────────────────────────────────────────────────────
ENV_VAR_RE = re.compile(
    r'process\.env\.([A-Z][A-Z0-9_]{2,})'
    r'(?:\s*(?:=\s*["\']([^"\']{1,300})["\']|\|\|\s*["\']([^"\']{1,300})["\']))?'
)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(threadName)-20s  %(message)s"


def setup_logging(verbose: bool) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("harvester")
    logger.setLevel(level)
    if not logger.handlers:          # only add handler once
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(h)
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────────────────

def normalise_url(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith("data:") or href.startswith("javascript:"):
        return None
    url = urljoin(base, href)
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return None
    return url


def url_to_filename(url: str, output_dir: Path) -> Path:
    parsed = urlparse(url)
    rel = parsed.path.lstrip("/") or "index"
    safe = re.sub(r'[<>:"|?*]', "_", rel)
    path = output_dir / safe
    if parsed.query:
        suffix = hashlib.md5(parsed.query.encode()).hexdigest()[:6]
        path = path.with_name(path.name + f"__q{suffix}")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# JS URL extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_js_urls(content: str, page_url: str, base_origin: str) -> set[str]:
    found: set[str] = set()

    for m in re.finditer(
        r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        content, re.IGNORECASE,
    ):
        u = normalise_url(page_url, m.group(1))
        if u: found.add(u)

    for m in re.finditer(r'["\`](/_next/static/[^\s\'"<>`]+\.js)["\`]', content):
        u = normalise_url(base_origin, m.group(1))
        if u: found.add(u)

    for m in re.finditer(r'"(/_next/static/chunks/[^"]+\.js)"', content):
        u = normalise_url(base_origin, m.group(1))
        if u: found.add(u)

    for m in re.finditer(r'["\']([a-f0-9]{16}\.js)["\']', content):
        for prefix in ("/_next/static/chunks/", "/_next/static/chunks/pages/"):
            u = normalise_url(base_origin, prefix + m.group(1))
            if u: found.add(u)

    # Webpack chunk map: {123:"abc123def456", ...}
    for block in WEBPACK_CHUNK_MAP_RE.finditer(content):
        for entry in WEBPACK_CHUNK_ENTRY_RE.finditer(block.group(0)):
            h = entry.group(2)
            for prefix in ("/_next/static/chunks/", "/_next/static/chunks/pages/"):
                u = normalise_url(base_origin, f"{prefix}{h}.js")
                if u: found.add(u)

    origin_host = urlparse(base_origin).netloc
    return {
        u for u in found
        if urlparse(u).netloc == origin_host
        and not re.search(r'/_next/static/(?:css|media)/', urlparse(u).path)
    }


def extract_build_manifest_url(html: str, base_origin: str) -> str | None:
    m = BUILD_MANIFEST_RE.search(html)
    if m:
        return urljoin(base_origin, f"/_next/static/{m.group(1)}/_buildManifest.js")
    return None


def parse_build_manifest(js_text: str, base_origin: str) -> set[str]:
    urls: set[str] = set()
    for m in re.finditer(r'"(static/[^"]+\.js)"', js_text):
        u = normalise_url(base_origin, "/_next/" + m.group(1))
        if u: urls.add(u)
    return urls


# ─────────────────────────────────────────────────────────────────────────────
# Beautifier
# ─────────────────────────────────────────────────────────────────────────────

def beautify_js(content: str, logger: logging.Logger) -> str:
    if not JSBEAUTIFIER_AVAILABLE:
        return content
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 2
    opts.wrap_line_length = 0
    opts.unescape_strings = True
    opts.space_before_conditional = True
    try:
        return jsbeautifier.beautify(content, opts)
    except Exception as e:
        logger.warning(f"jsbeautifier failed: {e}")
        return content


# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────

def make_session(user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent":      user_agent,
        "Accept":          "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br" if BROTLI_AVAILABLE else "gzip, deflate",
        "Connection":      "keep-alive",
        "Sec-Fetch-Dest":  "script",
        "Sec-Fetch-Mode":  "no-cors",
        "Sec-Fetch-Site":  "same-origin",
    })
    return s


def decompress_response(resp: requests.Response, logger: logging.Logger) -> bytes:
    raw = resp.content
    enc = resp.headers.get("Content-Encoding", "").lower().strip()

    if not enc or enc == "identity":
        return raw
    if enc in ("gzip", "x-gzip"):
        if raw[:2] == b'\x1f\x8b':
            try: return gzip.decompress(raw)
            except Exception as e: logger.warning(f"  gzip decompress failed: {e}")
        return raw
    if enc == "deflate":
        if raw[:1] in (b'\x78', b'\x9c'):
            try: return zlib.decompress(raw)
            except Exception:
                try: return zlib.decompress(raw, -zlib.MAX_WBITS)
                except Exception as e: logger.warning(f"  deflate decompress failed: {e}")
        return raw
    if enc == "br" and BROTLI_AVAILABLE:
        sample = raw[:64]
        non_print = sum(1 for b in sample if b < 0x20 or b > 0x7e)
        if sample and non_print / len(sample) > 0.30:
            try: return brotli.decompress(raw)
            except Exception as e: logger.debug(f"  brotli skip: {e}")
        return raw
    return raw


def resp_to_text(resp: requests.Response, logger: logging.Logger) -> str:
    raw = decompress_response(resp, logger)
    try:    return raw.decode("utf-8")
    except: return raw.decode("latin-1")


# ─────────────────────────────────────────────────────────────────────────────
# Secret scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_secrets(content: str, filename: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple] = set()
    lines = content.splitlines()

    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            value = (m.group(1) if m.lastindex and m.group(1) else m.group(0)).strip()
            if len(value) < 6 or re.match(r'^[A-Z_]+$', value):
                continue
            key = (label, value[:80])
            if key in seen:
                continue
            seen.add(key)
            line_no = content[:m.start()].count('\n') + 1
            ctx = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""
            findings.append({
                "label":   label,
                "value":   value[:200],
                "file":    filename,
                "line":    line_no,
                "context": ctx,
            })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Route extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_routes(content: str, filename: str) -> list[dict]:
    found: dict[str, dict] = {}
    for pattern in ROUTE_PATTERNS:
        for m in pattern.finditer(content):
            path = m.group(1).strip()
            if ROUTE_NOISE_RE.search(path): continue
            if len(path) < 4 or len(path) > 200: continue
            if not path.startswith("/"): continue
            if re.search(r'(?:\.[a-z]{2,4}$|\.\.)', path): continue
            parts = [p for p in path.split('/') if p]
            if len(parts) == 1 and len(parts[0]) < 3: continue
            if path not in found:
                line_no = content[:m.start()].count('\n') + 1
                found[path] = {"path": path, "file": filename, "line": line_no}
    return list(found.values())


# ─────────────────────────────────────────────────────────────────────────────
# Env var leakage
# ─────────────────────────────────────────────────────────────────────────────

def scan_env_vars(content: str, filename: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()
    for m in ENV_VAR_RE.finditer(content):
        name  = m.group(1)
        value = m.group(2) or m.group(3) or None
        if name in seen: continue
        seen.add(name)
        is_public = name.startswith("NEXT_PUBLIC_")
        if not is_public or value:
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                "name":   name,
                "value":  value,
                "public": is_public,
                "leaked": value is not None,
                "file":   filename,
                "line":   line_no,
            })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# __NEXT_DATA__ + RSC harvester
# ─────────────────────────────────────────────────────────────────────────────

def harvest_next_data(
    html: str,
    output_dir: Path,
    base_origin: str,
    logger: logging.Logger,
) -> set[str]:
    """
    Extract __NEXT_DATA__ blob and RSC payloads from an HTML page.
    Returns a set of /_next/data/* URLs to probe.
    """
    extra_urls: set[str] = set()

    # ── __NEXT_DATA__ ──────────────────────────────────────────────────────
    m = re.search(
        r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>\s*(\{.+?\})\s*</script>',
        html, re.DOTALL,
    )
    if m:
        try:
            data = json.loads(m.group(1))
            path = output_dir / "_next_data.json"
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info(f"[NEXT_DATA] Extracted __NEXT_DATA__ → {path}")

            build_id = data.get("buildId", "")
            if build_id:
                logger.info(f"[NEXT_DATA] Build ID: {build_id}")
                # Probe standard data routes
                for route in ("/", "/index", "/dashboard", "/settings",
                               "/admin", "/profile", "/account"):
                    u = urljoin(base_origin, f"/_next/data/{build_id}{route}.json")
                    extra_urls.add(u)

                # Also extract page-specific route from the blob itself
                page_props_page = data.get("page", "")
                if page_props_page and page_props_page not in ("/", "/_error"):
                    u = urljoin(base_origin, f"/_next/data/{build_id}{page_props_page}.json")
                    extra_urls.add(u)

            # Scan for secrets in the data blob too
            props_str = json.dumps(data)
            if len(props_str) > 10:
                logger.debug(f"[NEXT_DATA] Props size: {len(props_str):,} chars — scanning")
        except json.JSONDecodeError as e:
            logger.warning(f"[NEXT_DATA] JSON parse failed: {e}")

    # ── React Server Component streaming payload ──────────────────────────
    rsc_matches = re.findall(
        r'<script>\s*self\.__next_f\s*=\s*self\.__next_f\s*\|\|\s*\[\]\s*;?\s*'
        r'self\.__next_f\.push\((.+?)\)\s*</script>',
        html, re.DOTALL,
    )
    if rsc_matches:
        rsc_out = output_dir / "_rsc_payloads.txt"
        with open(rsc_out, "w", encoding="utf-8") as f:
            for chunk in rsc_matches:
                f.write(chunk + "\n---\n")
        logger.info(f"[RSC] Saved {len(rsc_matches)} RSC chunks → {rsc_out}")

    # ── App Router inline flight data (__next_f arrays in any format) ──────
    # Next.js 13+ App Router embeds flight data differently
    flight_matches = re.findall(r'\["([0-9a-f]+)","([^"]+)"\]', html)
    if flight_matches:
        logger.debug(f"[RSC] Found {len(flight_matches)} App Router flight segments")

    return extra_urls


# ─────────────────────────────────────────────────────────────────────────────
# Source map recovery
# ─────────────────────────────────────────────────────────────────────────────

def recover_sourcemap(
    js_content: str,
    js_url: str,
    output_dir: Path,
    session: requests.Session,
    timeout: tuple,
    logger: logging.Logger,
) -> int:
    """
    Detect, fetch (or decode inline), and reconstruct source files from a
    JS sourcemap. Returns number of source files written.
    """
    # Inline base64 sourcemap
    inline_m = INLINE_SOURCEMAP_RE.search(js_content)
    if inline_m:
        try:
            map_data = json.loads(base64.b64decode(inline_m.group(1)).decode("utf-8"))
            logger.info(f"[SRCMAP] Inline map in {Path(urlparse(js_url).path).name}")
            return _write_sources(map_data, js_url, output_dir, logger)
        except Exception as e:
            logger.warning(f"[SRCMAP] Inline decode failed: {e}")
            return 0

    # External .map reference
    url_m = SOURCEMAP_URL_RE.search(js_content)
    if not url_m:
        return 0

    map_ref = url_m.group(1).strip()
    if map_ref.startswith("data:"):
        return 0

    map_url = normalise_url(js_url, map_ref)
    if not map_url:
        return 0

    logger.info(f"[SRCMAP] Fetching {map_url}")
    try:
        r = session.get(map_url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        raw = decompress_response(r, logger)
        map_data = json.loads(raw.decode("utf-8", errors="replace"))
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code
        if code != 404:
            logger.warning(f"[SRCMAP] HTTP {code} for {map_url}")
        return 0
    except Exception as e:
        logger.warning(f"[SRCMAP] Failed: {e}")
        return 0

    # Save raw .map
    mp = url_to_filename(map_url, output_dir)
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(json.dumps(map_data, indent=2), encoding="utf-8")

    return _write_sources(map_data, js_url, output_dir, logger)


def _write_sources(map_data: dict, js_url: str, output_dir: Path, logger: logging.Logger) -> int:
    sources          = map_data.get("sources", [])
    sources_content  = map_data.get("sourcesContent", [])

    if not sources:
        return 0

    chunk_name = Path(urlparse(js_url).path).stem
    base_dir   = output_dir / "sourcemaps" / re.sub(r'[^\w\-]', '_', chunk_name)
    recovered  = 0

    for i, src_path in enumerate(sources):
        if not src_path:
            continue
        # Strip webpack:// and file:// prefixes
        src_path = re.sub(r'^(?:webpack://[^/]*/|file://)', '', src_path)
        src_path = src_path.lstrip("./").lstrip("/")

        # Skip node_modules (except react internals which can be interesting)
        if "node_modules" in src_path:
            if not any(x in src_path for x in ("react-dom", "next/")):
                continue

        content = (
            sources_content[i]
            if i < len(sources_content) and sources_content[i]
            else f"// source content unavailable: {src_path}\n"
        )

        out = base_dir / Path(src_path)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8", errors="replace")
            recovered += 1
        except Exception as e:
            logger.debug(f"[SRCMAP] write failed {out}: {e}")

    if recovered:
        logger.info(f"[SRCMAP] ✔ {recovered} source files → {base_dir}")
    return recovered


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_subdomains(content: str, apex_domain: str) -> set[str]:
    """
    Find all subdomains of apex_domain referenced in text content.
    apex_domain should be the registrable domain, e.g. "findtender.ca".
    Returns a set of fully-qualified subdomain hostnames, excluding www
    and the apex itself.
    """
    # Escape dots in apex for use in regex
    apex_esc = re.escape(apex_domain)

    # Match any hostname ending in .apex_domain, preceded by word boundary or quote/slash
    pattern = re.compile(
        r'(?:https?://)?'                        # optional scheme
        r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'  # first label
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'  # more labels
        r'\.' + apex_esc + r')'                  # must end with .apex_domain
        r'(?=[/"\'\s\]\)\}>:,]|$)',              # followed by delimiter or EOL
        re.IGNORECASE,
    )

    found: set[str] = set()
    for m in pattern.finditer(content):
        host = m.group(1).lower().rstrip('.')
        # Skip the apex itself and bare www
        if host == apex_domain:
            continue
        if host == f"www.{apex_domain}":
            continue
        # Skip very long matches (likely false positives in minified strings)
        if len(host) > 253:
            continue
        found.add(host)

    return found


def get_apex_domain(netloc: str) -> str:
    """
    Extract the registrable apex domain from a netloc string.
    Handles common two-part TLDs (co.uk, com.au, etc.) heuristically.
    e.g. "api.findtender.ca" -> "findtender.ca"
         "app.example.co.uk" -> "example.co.uk"
    """
    # Strip port
    host = netloc.split(':')[0].lower()
    parts = host.split('.')

    # Known two-part TLDs (non-exhaustive but covers common cases)
    two_part_tlds = {
        'co.uk', 'co.nz', 'co.za', 'co.jp', 'co.in', 'co.id', 'co.ke',
        'com.au', 'com.br', 'com.mx', 'com.ar', 'com.co', 'com.sg',
        'net.au', 'org.au', 'gov.au', 'edu.au',
        'org.uk', 'net.uk', 'gov.uk', 'ac.uk',
        'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    }

    if len(parts) >= 3:
        two_part = '.'.join(parts[-2:])
        if two_part in two_part_tlds:
            # registrable = parts[-3] + two_part_tld
            return '.'.join(parts[-3:])

    # Default: last two labels
    if len(parts) >= 2:
        return '.'.join(parts[-2:])

    return host


# ─────────────────────────────────────────────────────────────────────────────
# Harvester
# ─────────────────────────────────────────────────────────────────────────────

class Harvester:

    def __init__(
        self,
        target: str,
        output_dir: Path,
        user_agent: str,
        threads: int,
        depth: int,
        timeout: int,
        connect_timeout: int,
        retries: int,
        beautify: bool,
        scan: bool,
        sourcemaps: bool,
        extra_pages: list[str],
        verbose: bool,
        delay: float,
    ):
        parsed = urlparse(target)
        self.base_origin = f"{parsed.scheme}://{parsed.netloc}"
        self.target      = target
        self.apex_domain = get_apex_domain(parsed.netloc)
        self.output_dir  = output_dir
        self.threads     = threads
        self.max_depth   = depth
        self.timeout     = (connect_timeout, timeout)
        self.retries     = retries
        self.do_beautify = beautify
        self.do_scan     = scan
        self.do_srcmaps  = sourcemaps
        self.extra_pages = extra_pages
        self.delay       = delay

        self.logger  = setup_logging(verbose)
        self.session = make_session(user_agent)

        # BFS
        self._visited:      set[str]               = set()
        self._visited_lock: Lock                   = Lock()
        self._queue:        deque[tuple[str, int]] = deque()
        self._queue_lock:   Lock                   = Lock()

        # Results
        self._saved:        list[str]        = []
        self._saved_lock    = Lock()
        self._errors:       list[str]        = []
        self._errors_lock   = Lock()
        self._secrets:      list[dict]       = []
        self._secrets_lock  = Lock()
        self._routes:       dict[str, dict]  = {}
        self._routes_lock   = Lock()
        self._env_vars:     list[dict]       = []
        self._env_lock      = Lock()
        self._sm_recovered: int              = 0
        self._sm_lock       = Lock()
        self._subdomains:   set[str]         = set()
        self._subdomains_lock = Lock()
        self._fetch_count   = 0
        self._fetch_lock    = Lock()

        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── State ─────────────────────────────────────────────────────────────────

    def _mark_visited(self, url: str) -> bool:
        with self._visited_lock:
            if url in self._visited: return False
            self._visited.add(url);  return True

    def _enqueue(self, url: str, depth: int):
        if depth <= self.max_depth:
            with self._queue_lock:
                self._queue.append((url, depth))

    def _save_file(self, url: str, content: str) -> Path:
        p = url_to_filename(url, self.output_dir)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", errors="replace")
        with self._saved_lock:
            self._saved.append(str(p))
        self.logger.info(f"  ✔ saved  {p}  [{len(content):,} chars]")
        return p

    def _record_error(self, url: str, reason: str):
        msg = f"{url}  →  {reason}"
        with self._errors_lock: self._errors.append(msg)
        self.logger.error(f"  ✘ {msg}")

    def _add_secrets(self, findings: list[dict]):
        if findings:
            with self._secrets_lock: self._secrets.extend(findings)

    def _add_routes(self, routes: list[dict]):
        if routes:
            with self._routes_lock:
                for r in routes:
                    self._routes[r["path"]] = r

    def _add_env_vars(self, findings: list[dict]):
        if findings:
            with self._env_lock:
                existing = {e["name"] for e in self._env_vars}
                for f in findings:
                    if f["name"] not in existing:
                        self._env_vars.append(f)
                        existing.add(f["name"])

    def _add_subdomains(self, content: str):
        found = extract_subdomains(content, self.apex_domain)
        if found:
            with self._subdomains_lock:
                new = found - self._subdomains
                if new:
                    self._subdomains.update(new)
                    for sd in sorted(new):
                        self.logger.info(f"  🌐 subdomain found: {sd}")

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _fetch_with_retry(self, url: str, label: str) -> requests.Response | None:
        last_err = "unknown"
        for attempt in range(1, self.retries + 1):
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                r.raise_for_status()
                return r
            except requests.exceptions.HTTPError as e:
                last_err = f"HTTP {e.response.status_code}"
                if e.response.status_code < 500:
                    self.logger.debug(f"[{label}] {last_err}")
                    return None
                self.logger.warning(f"[{label}] attempt {attempt}: {last_err}")
            except requests.exceptions.Timeout:
                last_err = "Timeout"
                self.logger.warning(f"[{label}] attempt {attempt}: timed out")
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
            except requests.exceptions.RequestException as e:
                last_err = str(e)
                self.logger.warning(f"[{label}] attempt {attempt}: {last_err}")
                if attempt < self.retries:
                    time.sleep(2)
        self.logger.error(f"[{label}] all retries failed: {last_err}")
        return None

    # ── Analysis pipeline ─────────────────────────────────────────────────────

    def _analyse(self, url: str, text: str):
        """Post-save analysis: secrets, routes, env vars, source maps."""
        if not url.split("?")[0].endswith(".js"):
            return

        rel = str(url_to_filename(url, self.output_dir))

        if self.do_scan:
            s = scan_secrets(text, rel)
            if s:
                self.logger.info(f"  🔑 {len(s)} secret(s) → {Path(rel).name}")
            self._add_secrets(s)

            ev = scan_env_vars(text, rel)
            self._add_env_vars(ev)
            leaked = [e["name"] for e in ev if e["leaked"]]
            if leaked:
                self.logger.info(f"  📦 Leaked env: {', '.join(leaked)}")

        routes = extract_routes(text, rel)
        if routes:
            self.logger.debug(f"  🗺  {len(routes)} routes → {Path(rel).name}")
        self._add_routes(routes)

        # Subdomain discovery
        self._add_subdomains(text)

        if self.do_srcmaps:
            n = recover_sourcemap(text, url, self.output_dir,
                                  self.session, self.timeout, self.logger)
            if n:
                with self._sm_lock:
                    self._sm_recovered += n

    # ── BFS fetch ─────────────────────────────────────────────────────────────

    def fetch_url(self, url: str, depth: int) -> tuple[str, str | None]:
        if not self._mark_visited(url):
            return url, None

        if self.delay > 0:
            time.sleep(self.delay)

        with self._fetch_lock:
            self._fetch_count += 1
            seq = self._fetch_count

        self.logger.info(f"[{seq:04d}] depth={depth}  GET  {url}")

        resp = None
        last_err = "unknown"
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                resp.raise_for_status()
                break
            except requests.exceptions.HTTPError as e:
                last_err = f"HTTP {e.response.status_code}"
                if e.response.status_code < 500:
                    self._record_error(url, last_err)
                    return url, None
                self.logger.warning(f"  attempt {attempt}: {last_err}")
            except requests.exceptions.Timeout:
                last_err = "Timeout"
                self.logger.warning(f"  attempt {attempt}: timed out")
                if attempt < self.retries: time.sleep(2 ** attempt)
            except requests.exceptions.RequestException as e:
                last_err = str(e)
                self.logger.warning(f"  attempt {attempt}: {last_err}")
                if attempt < self.retries: time.sleep(1)
        else:
            self._record_error(url, last_err)
            return url, None

        ct  = resp.headers.get("Content-Type", "")
        ce  = resp.headers.get("Content-Encoding", "identity")
        self.logger.debug(f"  → {resp.status_code}  {len(resp.content):,}b  CT={ct}  CE={ce}")

        raw    = decompress_response(resp, self.logger)
        sample = raw[:512]

        if b'\x00' in sample:
            self.logger.warning(f"  ⚠ binary after decompress — saving as latin-1")
            text = raw.decode("latin-1")
        else:
            try:    text = raw.decode("utf-8")
            except: text = raw.decode("latin-1")

        is_js = url.split("?")[0].endswith(".js") or "javascript" in ct
        if is_js and self.do_beautify and b'\x00' not in sample:
            text = beautify_js(text, self.logger)

        self._save_file(url, text)
        self._analyse(url, text)

        for child in extract_js_urls(text, url, self.base_origin):
            self._enqueue(child, depth + 1)

        return url, text

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def _bootstrap_page(self, url: str, label: str) -> str | None:
        self.logger.info(f"[{label}] Seeding from: {url}")
        resp = self._fetch_with_retry(url, label)
        if resp is None:
            self.logger.error(f"[{label}] Unreachable — skipping")
            return None

        html = resp_to_text(resp, self.logger)
        self.logger.info(f"[{label}] {resp.status_code}  {len(html):,} bytes")

        # Save HTML
        safe = re.sub(r'[^\w/\-]', '_',
                      urlparse(url).path.strip("/") or "index")
        html_out = self.output_dir / f"{safe}.html"
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(html, encoding="utf-8", errors="replace")
        self.logger.info(f"[{label}] HTML → {html_out}")

        if self.do_scan:
            self._add_secrets(scan_secrets(html, str(html_out)))

        # Subdomain discovery in HTML
        self._add_subdomains(html)

        # __NEXT_DATA__ + RSC
        data_urls = harvest_next_data(html, self.output_dir, self.base_origin, self.logger)
        for u in data_urls:
            self._enqueue(u, 1)

        # JS chunks
        js_urls = extract_js_urls(html, url, self.base_origin)
        self.logger.info(f"[{label}] {len(js_urls)} JS URLs enqueued")
        for u in js_urls:
            self._enqueue(u, 1)

        return html

    def _bootstrap(self):
        common = [
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/framework.js",
            "/_next/static/chunks/polyfills.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/pages/_app.js",
            "/_next/static/chunks/pages/index.js",
        ]

        html = self._bootstrap_page(self.target, "BOOT")

        if html:
            manifest_url = extract_build_manifest_url(html, self.base_origin)
            if manifest_url:
                self.logger.info(f"[BOOT] _buildManifest → {manifest_url}")
                mr = self._fetch_with_retry(manifest_url, "MANIFEST")
                if mr:
                    mt = resp_to_text(mr, self.logger)
                    chunks = parse_build_manifest(mt, self.base_origin)
                    self.logger.info(f"[BOOT] manifest: {len(chunks)} chunks")
                    self._mark_visited(manifest_url)
                    self._save_file(manifest_url,
                                    beautify_js(mt, self.logger) if self.do_beautify else mt)
                    for u in chunks: self._enqueue(u, 1)
            else:
                self.logger.warning("[BOOT] No _buildManifest detected")

        for extra in self.extra_pages:
            seed = urljoin(self.base_origin, extra)
            if seed != self.target:
                self._bootstrap_page(seed, f"SEED:{extra}")

        for p in common:
            self._enqueue(urljoin(self.base_origin, p), 1)

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self):
        self.logger.info("=" * 72)
        self.logger.info(f"  Target       : {self.target}")
        self.logger.info(f"  Origin       : {self.base_origin}")
        self.logger.info(f"  Output dir   : {self.output_dir}")
        self.logger.info(f"  Threads      : {self.threads}")
        self.logger.info(f"  Max depth    : {self.max_depth}")
        self.logger.info(f"  Timeout      : connect={self.timeout[0]}s  read={self.timeout[1]}s")
        self.logger.info(f"  Retries      : {self.retries}")
        self.logger.info(f"  Beautify     : {self.do_beautify}")
        self.logger.info(f"  Scan         : {self.do_scan}")
        self.logger.info(f"  Source maps  : {self.do_srcmaps}")
        self.logger.info(f"  Extra pages  : {', '.join(self.extra_pages) or 'none'}")
        self.logger.info(f"  jsbeautifier : {'yes' if JSBEAUTIFIER_AVAILABLE else 'NOT installed'}")
        self.logger.info(f"  brotli       : {'yes' if BROTLI_AVAILABLE else 'NOT installed'}")
        self.logger.info("=" * 72)

        t0 = time.time()
        self._bootstrap()

        self.logger.info(f"[RUN] BFS — {self.threads} workers")
        with ThreadPoolExecutor(max_workers=self.threads,
                                thread_name_prefix="worker") as ex:
            futures: dict = {}

            def drain():
                while True:
                    with self._queue_lock:
                        if not self._queue: break
                        url, depth = self._queue.popleft()
                    with self._visited_lock:
                        if url in self._visited: continue
                    futures[ex.submit(self.fetch_url, url, depth)] = url

            drain()
            while futures:
                for f in as_completed(list(futures.keys()),
                                      timeout=self.timeout[1] + 5):
                    try:    f.result()
                    except Exception as e:
                        self.logger.error(f"[RUN] {e}")
                    del futures[f]
                    drain()
                drain()
                for f in list(futures.keys()):
                    if f.done():
                        try:    f.result()
                        except Exception as e:
                            self.logger.error(f"[RUN] {e}")
                        del futures[f]

        elapsed = time.time() - t0
        self._write_reports()

        self.logger.info("")
        self.logger.info("=" * 72)
        self.logger.info("  HARVEST COMPLETE")
        self.logger.info(f"  Elapsed      : {elapsed:.1f}s")
        self.logger.info(f"  Fetched      : {self._fetch_count} URLs")
        self.logger.info(f"  Saved        : {len(self._saved)} files")
        self.logger.info(f"  Errors       : {len(self._errors)}")
        self.logger.info(f"  Secrets      : {len(self._secrets)} findings")
        self.logger.info(f"  Routes       : {len(self._routes)} unique")
        self.logger.info(f"  Env vars     : {len(self._env_vars)} "
                         f"({sum(1 for e in self._env_vars if e['leaked'])} leaked)")
        self.logger.info(f"  Src files    : {self._sm_recovered} from source maps")
        self.logger.info(f"  Subdomains   : {len(self._subdomains)} discovered")
        self.logger.info(f"  Output dir   : {self.output_dir.resolve()}")
        self.logger.info("=" * 72)

        if self._errors:
            self.logger.info("\n  ERRORS:")
            for e in self._errors:
                self.logger.info(f"    • {e}")

        if self._secrets:
            self.logger.info(f"\n  ⚠  TOP FINDINGS (full list in _secrets.json):")
            shown: set = set()
            for s in self._secrets[:25]:
                k = (s["label"], s["value"][:40])
                if k not in shown:
                    shown.add(k)
                    self.logger.info(
                        f"    [{s['label']}]  {s['value'][:80]}"
                        f"  ({Path(s['file']).name}:{s['line']})"
                    )

        # ── Interactive subdomain expansion ───────────────────────────────────
        self._prompt_subdomain_expansion()

    # ── Subdomain expansion prompt ────────────────────────────────────────────

    def _prompt_subdomain_expansion(self):
        """
        After a completed harvest, if subdomains were discovered, present them
        interactively and let the user pick which ones to expand into new runs.
        """
        if not self._subdomains:
            return

        # Sort: api/app/admin first (higher recon value), then alphabetical
        priority = {"api", "app", "admin", "dashboard", "dev", "staging",
                    "backend", "internal", "gateway", "auth", "cdn", "static"}
        ordered = sorted(
            self._subdomains,
            key=lambda h: (0 if h.split('.')[0] in priority else 1, h),
        )

        print("\n" + "─" * 72)
        print(f"  🌐  SUBDOMAINS DISCOVERED ({len(ordered)} unique)")
        print("─" * 72)
        for i, sd in enumerate(ordered, 1):
            tag = "  ★" if sd.split('.')[0] in priority else "   "
            print(f"  [{i:2d}]{tag}  {sd}")
        print()
        print("  Enter numbers to expand (e.g. 1,3,5), 'all', or ENTER to skip:")
        print("  (★ = likely high-value target)")

        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not raw:
            self.logger.info("[EXPAND] Skipped subdomain expansion.")
            return

        if raw.lower() == "all":
            selected = list(ordered)
        else:
            selected = []
            for part in re.split(r'[,\s]+', raw):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(ordered):
                        selected.append(ordered[idx])
                    else:
                        print(f"  [!] Invalid index: {part}")

        if not selected:
            self.logger.info("[EXPAND] No valid subdomains selected.")
            return

        print()
        self.logger.info(f"[EXPAND] Launching {len(selected)} subdomain harvest(s)…")

        for subdomain in selected:
            sub_url    = f"{urlparse(self.target).scheme}://{subdomain}/"
            sub_outdir = self.output_dir.parent / subdomain.replace('.', '_')

            self.logger.info(f"[EXPAND] ── {sub_url}  →  {sub_outdir}")
            print()

            sub = Harvester(
                target          = sub_url,
                output_dir      = sub_outdir,
                user_agent      = self.session.headers.get("User-Agent", DEFAULT_UA),
                threads         = self.threads,
                depth           = self.max_depth,
                timeout         = self.timeout[1],
                connect_timeout = self.timeout[0],
                retries         = self.retries,
                beautify        = self.do_beautify,
                scan            = self.do_scan,
                sourcemaps      = self.do_srcmaps,
                extra_pages     = [],   # fresh start, no extra pages
                verbose         = self.logger.level == logging.DEBUG,
                delay           = self.delay,
            )
            try:
                sub.run()
            except Exception as e:
                self.logger.error(f"[EXPAND] {subdomain} failed: {e}")

    # ── Reports ───────────────────────────────────────────────────────────────

    def _write_reports(self):
        o = self.output_dir

        # Summary
        (o / "_harvest_summary.json").write_text(json.dumps({
            "target":          self.target,
            "apex_domain":     self.apex_domain,
            "saved_files":     self._saved,
            "errors":          self._errors,
            "secrets_count":   len(self._secrets),
            "routes_count":    len(self._routes),
            "env_vars_count":  len(self._env_vars),
            "sourcemaps_recovered": self._sm_recovered,
            "subdomains":      sorted(self._subdomains),
        }, indent=2), encoding="utf-8")

        # Secrets
        if self._secrets:
            (o / "_secrets.json").write_text(
                json.dumps(sorted(self._secrets,
                                  key=lambda x: (x["label"], x["file"])),
                           indent=2), encoding="utf-8")
            self.logger.info(f"  🔑 _secrets.json  ({len(self._secrets)} findings)")

        # Routes
        if self._routes:
            routes_list = sorted(self._routes.values(), key=lambda x: x["path"])
            (o / "_routes.json").write_text(
                json.dumps(routes_list, indent=2), encoding="utf-8")
            with open(o / "_routes.txt", "w") as f:
                for r in routes_list:
                    f.write(r["path"] + "\n")
            self.logger.info(f"  🗺  _routes.txt  ({len(routes_list)} endpoints)")

        # Env vars
        if self._env_vars:
            leaked = sum(1 for e in self._env_vars if e["leaked"])
            (o / "_env_vars.json").write_text(
                json.dumps(
                    sorted(self._env_vars, key=lambda x: (not x["leaked"], x["name"])),
                    indent=2), encoding="utf-8")
            self.logger.info(f"  📦 _env_vars.json  ({len(self._env_vars)} vars, {leaked} with values)")

        # Subdomains
        if self._subdomains:
            priority = {"api", "app", "admin", "dashboard", "dev", "staging",
                        "backend", "internal", "gateway", "auth"}
            ordered = sorted(
                self._subdomains,
                key=lambda h: (0 if h.split('.')[0] in priority else 1, h),
            )
            (o / "_subdomains.txt").write_text(
                "\n".join(ordered) + "\n", encoding="utf-8")
            self.logger.info(f"  🌐 _subdomains.txt  ({len(ordered)} hosts)")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="nextjs_harvester",
        description="Next.js / React SPA offensive recon harvester",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("target",               help="Target URL  (e.g. https://findtender.ca/)")
    p.add_argument("-o", "--output",       default=None, metavar="DIR",
                                           help="Output directory (default: ./<apex-domain>)")
    p.add_argument("-t", "--threads",      type=int, default=DEFAULT_THREADS,  metavar="N")
    p.add_argument("-d", "--depth",        type=int, default=DEFAULT_DEPTH,    metavar="N")
    p.add_argument("-p", "--page",         action="append", dest="pages",
                                           default=[], metavar="PATH",
                                           help="Extra seed page path(s)  (repeatable: -p /dashboard -p /admin)")
    p.add_argument("--timeout",            type=int, default=DEFAULT_TIMEOUT,    metavar="SEC")
    p.add_argument("--connect-timeout",    type=int, default=DEFAULT_CONNECT_TO, metavar="SEC")
    p.add_argument("--retries",            type=int, default=DEFAULT_RETRIES,    metavar="N")
    p.add_argument("-ua", "--user-agent",  default=DEFAULT_UA, metavar="UA")
    p.add_argument("--no-beautify",        action="store_true", default=False)
    p.add_argument("--no-scan",            action="store_true", default=False,
                                           help="Skip secret + env-var scanning")
    p.add_argument("--no-sourcemaps",      action="store_true", default=False,
                                           help="Skip source map recovery")
    p.add_argument("--delay",              type=float, default=0.0, metavar="SEC")
    p.add_argument("-v", "--verbose",      action="store_true", default=False)
    return p.parse_args()


def main():
    args = parse_args()
    if not JSBEAUTIFIER_AVAILABLE and not args.no_beautify:
        print("[WARN] pip install jsbeautifier", file=sys.stderr)

    # Derive output directory from apex domain if not explicitly set
    parsed_target = urlparse(args.target)
    apex = get_apex_domain(parsed_target.netloc)
    output_dir = Path(args.output) if args.output else Path(f"./{apex}")

    Harvester(
        target          = args.target,
        output_dir      = output_dir,
        user_agent      = args.user_agent,
        threads         = args.threads,
        depth           = args.depth,
        timeout         = args.timeout,
        connect_timeout = args.connect_timeout,
        retries         = args.retries,
        beautify        = not args.no_beautify,
        scan            = not args.no_scan,
        sourcemaps      = not args.no_sourcemaps,
        extra_pages     = args.pages,
        verbose         = args.verbose,
        delay           = args.delay,
    ).run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(1)
