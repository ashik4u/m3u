#!/usr/bin/env python3
"""
Resolve HLS (m3u8) final server URL(s) from a short/proxy URL.

Example:
    python resolve_hls.py https://a1xs.vip/700031
    python resolve_hls.py --chain https://a1xs.vip/700031

Requires:
    pip install requests

What it does:
    - Requests the given URL (no redirects) to capture a Location header if present.
    - Follows redirects and reports the final effective URL and optionally prints the full
      redirect chain (statuses and URLs) with --chain.
    - If the final response looks like an HLS playlist (m3u8), parses it and resolves
      relative URIs to absolute URLs.
    - Tries simple HTML fallbacks (meta refresh and JS location assignments) to
      detect redirect targets embedded in HTML.
    - Allows customizing headers (User-Agent, Referer) if needed.
"""
import argparse
import sys
import requests
from urllib.parse import urljoin
import re

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Accept": "*/*",
}

META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?([^"\'>]+)["\']?', re.IGNORECASE)
JS_LOCATION_RE = re.compile(r'location(?:\.href|\.assign)?\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

def get_location_header(url, headers=None, timeout=10):
    headers = headers or DEFAULT_HEADERS
    try:
        r = requests.get(url, headers=headers, allow_redirects=False, timeout=timeout)
    except Exception as e:
        print(f"[error] request failed: {e}")
        return None
    loc = r.headers.get("Location") or r.headers.get("location")
    print(f"[info] {url} -> status {r.status_code}")
    if loc:
        absolute = urljoin(url, loc)
        print(f"[info] Location header: {loc}")
        print(f"[info] Resolved Location -> {absolute}")
        return absolute
    print("[info] No Location header present")
    return None

def follow_and_inspect(url, headers=None, timeout=15, show_chain=False):
    headers = headers or DEFAULT_HEADERS
    s = requests.Session()
    try:
        r = s.get(url, headers=headers, allow_redirects=True, timeout=timeout)
    except Exception as e:
        print(f"[error] request failed: {e}")
        return None
    # Print redirect chain if requested
    if show_chain:
        if r.history:
            print("[info] Redirect chain (earliest -> latest):")
            for i, resp in enumerate(r.history, start=1):
                loc = resp.headers.get("Location")
                resolved_loc = urljoin(resp.url, loc) if loc else ""
                print(f"  {i}: {resp.status_code}  {resp.url}")
                if loc:
                    print(f"     -> Location: {loc}")
                    print(f"     -> Resolved: {resolved_loc}")
            # Final response
            print(f"  final: {r.status_code}  {r.url}")
        else:
            print("[info] No redirects observed (direct response).")
            print(f"  final: {r.status_code}  {r.url}")
    else:
        print(f"[info] Final URL: {r.url}")
        print(f"[info] Response status: {r.status_code}")
    ct = r.headers.get("Content-Type", "")
    print(f"[info] Content-Type: {ct}")
    return r

def parse_m3u8_and_resolve(text, base_url):
    """
    Return a list of absolute URLs found in the playlist content.
    Ignores comment and EXTINF lines.
    """
    lines = text.splitlines()
    urls = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        absolute = urljoin(base_url, ln)
        urls.append(absolute)
    return urls

def try_html_embedded_redirect(text, base_url):
    # meta refresh
    m = META_REFRESH_RE.search(text)
    if m:
        content = m.group(1)
        parts = content.split(';', 1)
        if len(parts) > 1 and 'url=' in parts[1].lower():
            url_part = parts[1].split('=', 1)[1].strip()
        else:
            url_part = parts[-1].strip()
        resolved = urljoin(base_url, url_part)
        print(f"[info] Meta-refresh target -> {resolved}")
        return resolved
    # simple JS assignment
    m2 = JS_LOCATION_RE.search(text)
    if m2:
        js_url = m2.group(1)
        resolved = urljoin(base_url, js_url)
        print(f"[info] JS location target -> {resolved}")
        return resolved
    return None

def main():
    p = argparse.ArgumentParser(description="Resolve final HLS/m3u8 server URLs from a short/proxy URL")
    p.add_argument("url", help="Short/proxy URL to resolve (e.g. https://a1xs.vip/700031)")
    p.add_argument("--no-follow", action="store_true", help="Only request without following redirects (inspect Location header)")
    p.add_argument("--referer", help="Set Referer header")
    p.add_argument("--user-agent", help="Set User-Agent header")
    p.add_argument("--chain", action="store_true", help="Print full redirect chain (statuses and URLs)")
    args = p.parse_args()

    headers = DEFAULT_HEADERS.copy()
    if args.referer:
        headers["Referer"] = args.referer
    if args.user_agent:
        headers["User-Agent"] = args.user_agent

    url = args.url
    # 1) Try capture Location header without following redirects
    loc = get_location_header(url, headers=headers)
    if args.no_follow:
        if loc:
            print(loc)
            return 0
        print("[info] no Location header and --no-follow set; exiting")
        return 1

    # 2) Follow redirects and inspect final response (optionally print chain)
    r = follow_and_inspect(url, headers=headers, show_chain=args.chain)
    if r is None:
        return 1

    final_url = r.url
    body = r.text or ""

    # 3) If content looks like m3u8, parse and print resolved URIs
    is_m3u8 = False
    ct = r.headers.get("Content-Type", "").lower()
    if "mpegurl" in ct or "vnd.apple.mpegurl" in ct or final_url.endswith(".m3u8") or "#EXTM3U" in body[:1000]:
        is_m3u8 = True

    if is_m3u8:
        print("[info] Detected playlist (m3u8). Parsing playlist entries...")
        entries = parse_m3u8_and_resolve(body, final_url)
        if not entries:
            print("[warn] No URIs found inside playlist")
        else:
            print("[result] Resolved playlist URIs:")
            for e in entries:
                print(e)
        return 0

    # 4) If not m3u8, try simple HTML embedded redirect patterns
    embedded = try_html_embedded_redirect(body, final_url)
    if embedded:
        print("[result] Embedded redirect detected ->", embedded)
        # Try one more time to capture Location header of the embedded URL
        get_location_header(embedded, headers=headers)
        # Optionally follow it and show chain for the embedded target
        rr = follow_and_inspect(embedded, headers=headers, show_chain=args.chain)
        if rr is not None and ("m3u8" in rr.headers.get("Content-Type", "") or "#EXTM3U" in rr.text[:1000] or rr.url.endswith(".m3u8")):
            entries = parse_m3u8_and_resolve(rr.text, rr.url)
            print("[result] Resolved playlist URIs from embedded target:")
            for e in entries:
                print(e)
        return 0

    # 5) Generic heuristics: search for any http(s)://... in body
    urls_found = re.findall(r'https?://[^\s\'"<>]+', body)
    if urls_found:
        print("[info] Other URLs found in response body (first 20):")
        for u in urls_found[:20]:
            print(u)
        return 0

    # 6) If we had a Location header earlier, print as fallback
    if loc:
        print("[fallback] Location header previously observed ->", loc)
        return 0

    print("[info] No direct m3u8 or redirect discovered. You may need to replicate headers/cookies or run the site JS in a headless browser (playwright/puppeteer) to obtain ephemeral URLs.")
    return 2

if __name__ == "__main__":
    sys.exit(main())