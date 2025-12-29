#!/usr/bin/env python3
"""Generate a final M3U with resolved URLs using resolved.py helpers.

Usage:
    python generate_final_m3u.py --input sky-uk-nz.m3u --output sky-uk-nz.resolved.m3u

Requires `requests` (same as resolved.py).
"""
import argparse
import re
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import resolved


def is_url_line(s):
    s = s.strip()
    return s.startswith('http://') or s.startswith('https://')


def resolve_to_final_urls(url, headers=None, skip_final_check=False):
    # If skip_final_check is requested, only attempt to capture a Location header
    # and return it (if present) without following or validating the final URL.
    if skip_final_check:
        loc = resolved.get_location_header(url, headers=headers)
        return [loc] if loc else [url]

    # Default behaviour: try a non-follow Location header first
    loc = resolved.get_location_header(url, headers=headers)
    # If Location header points to m3u8, follow it
    if loc and loc.endswith('.m3u8'):
        r = resolved.follow_and_inspect(loc, headers=headers)
    else:
        r = resolved.follow_and_inspect(url, headers=headers)

    if r is None:
        return [url]

    final_url = r.url
    body = r.text or ''
    ct = r.headers.get('Content-Type', '')

    # If response is m3u8/playlist
    if 'mpegurl' in ct or 'vnd.apple.mpegurl' in ct or final_url.endswith('.m3u8') or '#EXTM3U' in body[:1000]:
        entries = resolved.parse_m3u8_and_resolve(body, final_url)
        return entries or [final_url]

    # HTML embedded redirects
    embedded = resolved.try_html_embedded_redirect(body, final_url)
    if embedded:
        rr = resolved.follow_and_inspect(embedded, headers=headers)
        if rr is not None:
            if 'm3u8' in rr.headers.get('Content-Type', '') or '#EXTM3U' in rr.text[:1000] or rr.url.endswith('.m3u8'):
                entries = resolved.parse_m3u8_and_resolve(rr.text, rr.url)
                return entries or [rr.url]
            return [rr.url]

    # fallback: find any http(s) URLs in body
    found = re.findall(r'https?://[^\s\'\"<>]+', body)
    if found:
        return found

    if loc:
        return [loc]

    return [final_url]


def generate(input_path, output_path, headers=None):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    out_lines = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.strip().startswith('#EXTINF'):
            # keep EXTINF line
            out_lines.append(line.rstrip('\n'))
            # next non-empty line expected to be URL
            j = i + 1
            while j < n and lines[j].strip() == '':
                j += 1
            if j < n and is_url_line(lines[j]):
                url = lines[j].strip()
                print(f"[info] Resolving: {url}")
                # Determine skip flag from global arg if provided via closure
                skip_flag = getattr(generate, 'skip_final_check', False)
                final_urls = resolve_to_final_urls(url, headers=headers, skip_final_check=skip_flag)
                # prefer first resolved URL
                chosen = final_urls[0] if final_urls else url
                out_lines.append(chosen)
                i = j + 1
                continue
            else:
                # no url after EXTINF, just advance
                i += 1
                continue
        else:
            # preserve comments and other lines as-is
            out_lines.append(line.rstrip('\n'))
            i += 1

    # write output
    with open(output_path, 'w', encoding='utf-8') as f:
        for ln in out_lines:
            f.write(ln + '\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', '-i', default='sky-uk-nz.m3u')
    p.add_argument('--output', '-o', default='sky-uk-nz.resolved.m3u')
    p.add_argument('--referer', help='Optional Referer header')
    p.add_argument('--user-agent', help='Optional User-Agent header')
    p.add_argument('--skip-final-check', action='store_true', help='Do not follow to final server; only read initial Location header')
    args = p.parse_args()

    headers = resolved.DEFAULT_HEADERS.copy()
    if args.referer:
        headers['Referer'] = args.referer
    if args.user_agent:
        headers['User-Agent'] = args.user_agent

    # attach flag to generate function so inner loop can access it without changing signature
    setattr(generate, 'skip_final_check', args.skip_final_check)
    generate(args.input, args.output, headers=headers)
    print(f"[done] Wrote resolved M3U -> {args.output}")


if __name__ == '__main__':
    main()
