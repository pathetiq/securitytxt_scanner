"""
scan_security_txt.py

@author: [waps11](https://github.com/waps11) & [PathetiQ](https://github.com/PathetiQ)

Usage:
    python scan_security_txt.py urls.txt --output results.csv --save-files found_txt --concurrency 30

urls.txt: one hostname or URL per line. Examples:
    example.com
    https://gov.example.ca
    http://test.example

What it does:
 - For each host/URL it tries:
    1) <base>/.well-known/security.txt
    2) <base>/security.txt
 - Follows redirects, handles TLS.
 - Parses directives of form "Key: value" (RFC security.txt).
 - Writes CSV with results and JSON column for parsed directives.
 - Optionally saves full security.txt contents to a folder.
"""

import argparse
import asyncio
import csv
import json
import os
import re
from urllib.parse import urlparse, urljoin

import aiohttp

# Regular expression for "Key: value" lines (RFC)
_DIRECTIVE_RE = re.compile(r'^\s*([A-Za-z0-9\-\_]+)\s*:\s*(.+?)\s*$')

DEFAULT_USER_AGENT = "security-txt-scanner/1.0 (+https://example.org/)"

async def fetch_once(session, url, timeout):
    try:
        async with session.get(url, allow_redirects=True, timeout=timeout) as resp:
            text = await resp.text(errors='replace')
            return {
                "ok": True,
                "status": resp.status,
                "final_url": str(resp.url),
                "text": text,
                "headers": dict(resp.headers)
            }
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except aiohttp.ClientResponseError as e:
        return {"ok": False, "error": f"response_error: {e}"}
    except aiohttp.ClientConnectorError as e:
        return {"ok": False, "error": f"connect_error: {e}"}
    except Exception as e:
        return {"ok": False, "error": f"other_error: {e}"}

def parse_directives(text):
    """
    Parse 'Key: value' lines. Returns dict of lists (keys may repeat).
    """
    directives = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = _DIRECTIVE_RE.match(line)
        if m:
            k = m.group(1).strip()
            v = m.group(2).strip()
            directives.setdefault(k, []).append(v)
    return directives

def is_valid_security_txt(text):
    """
    Validate if the content is a proper security.txt file format.
    Returns True if valid, False otherwise.
    
    A valid security.txt should:
    1. Not be HTML content (no <html>, <!doctype>, etc.)
    2. Have at least one valid directive (Key: value format)
    3. Not be primarily error pages or other non-security.txt content
    """
    if not text or not text.strip():
        return False
    
    text_lower = text.lower().strip()
    
    # Check for HTML content indicators
    html_indicators = [
        '<!doctype html>',
        '<html',
        '<head>',
        '<body>',
        '<title>',
        '<script',
        '<style',
        '<meta',
        '<link',
        '<form',
        '<input',
        '<div',
        '<span',
        '<p>',
        '<h1>',
        '<h2>',
        '<h3>',
        'page not found',
        '404',
        'login',
        'sign in',
        'authentication'
    ]
    
    # If any HTML indicators are found, it's likely not a security.txt
    for indicator in html_indicators:
        if indicator in text_lower:
            return False
    
    # Parse directives to check if we have valid security.txt content
    directives = parse_directives(text)
    
    # Valid security.txt should have at least one directive
    if not directives:
        return False
    
    # Check for common security.txt directive names
    valid_directives = [
        'contact', 'expires', 'encryption', 'acknowledgments', 
        'preferred-languages', 'canonical', 'policy', 'hiring'
    ]
    
    # If we have at least one valid directive, consider it valid
    for directive in directives.keys():
        if directive.lower() in valid_directives:
            return True
    
    # If no recognized directives but we have some key:value pairs, 
    # it might still be valid (could be custom directives)
    if len(directives) > 0:
        return True
    
    return False

def normalize_base(input_url_or_host):
    """
    Convert inputs like 'example.com' or 'http://example.com/path' into base URL
    to test: scheme and netloc only.
    If scheme missing, default to https.
    """
    s = input_url_or_host.strip()
    if not s:
        return None
    if '://' not in s:
        s = 'https://' + s
    parsed = urlparse(s)
    if not parsed.netloc:
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base

async def worker(name, queue, session, timeout, results, save_folder):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        line_no, raw = item
        base = normalize_base(raw)
        if base is None:
            results.append({
                "input": raw,
                "path_checked": "",
                "status": "",
                "final_url": "",
                "error": "invalid input",
                "directives": {},
                "snippet": ""
            })
            queue.task_done()
            continue

        checked_paths = ['/.well-known/security.txt', '/security.txt']
        found_any = False
        aggregate_entry = None

        for path in checked_paths:
            url = urljoin(base, path)
            res = await fetch_once(session, url, timeout)
            if not res["ok"]:
                # record the attempt even if error (if nothing else found, keep last error)
                aggregate_entry = {
                    "input": raw,
                    "path_checked": path,
                    "status": "",
                    "final_url": "",
                    "error": res.get("error"),
                    "directives": {},
                    "snippet": ""
                }
                # try next path
                continue

            status = res["status"]
            text = res["text"]
            final_url = res["final_url"]

            if status == 200 and text.strip():
                # Validate that this is actually a security.txt file
                if not is_valid_security_txt(text):
                    # Not a valid security.txt, treat as if not found
                    aggregate_entry = {
                        "input": raw,
                        "path_checked": path,
                        "status": status,
                        "final_url": final_url,
                        "error": "invalid_security_txt_format",
                        "directives": {},
                        "snippet": text.strip()[:200].replace('\n','\\n')
                    }
                    # continue to try next path
                    continue
                
                directives = parse_directives(text)
                snippet = text.strip()[:1000].replace('\n', '\\n')
                aggregate_entry = {
                    "input": raw,
                    "path_checked": path,
                    "status": status,
                    "final_url": final_url,
                    "error": "",
                    "directives": directives,
                    "snippet": snippet
                }
                found_any = True

                if save_folder:
                    # sanitize filename
                    host = urlparse(final_url).netloc.replace(':','_')
                    fname = f"{host}__{path.strip('/').replace('/','_')}.txt"
                    safe_path = os.path.join(save_folder, fname)
                    try:
                        with open(safe_path, 'w', encoding='utf-8') as fh:
                            fh.write(text)
                    except Exception as e:
                        # don't fail overall if saving fails
                        pass

                # found good result; break (we prefer /.well-known if both exist; iteration order already does that)
                break
            else:
                # store the non-200 result (keep searching other path)
                aggregate_entry = {
                    "input": raw,
                    "path_checked": path,
                    "status": status,
                    "final_url": final_url,
                    "error": "",
                    "directives": {},
                    "snippet": (text.strip()[:200].replace('\n','\\n') if text else "")
                }
                # continue to try next path

        if aggregate_entry is None:
            aggregate_entry = {
                "input": raw,
                "path_checked": "",
                "status": "",
                "final_url": "",
                "error": "no_attempt",
                "directives": {},
                "snippet": ""
            }

        results.append(aggregate_entry)
        queue.task_done()

async def main(args):
    # read inputs
    with open(args.input, 'r', encoding='utf-8') as f:
        lines = [(i+1, l.strip()) for i,l in enumerate(f) if l.strip()]

    queue = asyncio.Queue()
    for item in lines:
        await queue.put(item)

    # workers
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    headers = {"User-Agent": args.user_agent}
    results = []
    save_folder = None
    if args.save_files:
        save_folder = args.save_files
        os.makedirs(save_folder, exist_ok=True)

    conn = aiohttp.TCPConnector(limit=args.concurrency, ssl=not args.insecure)

    async with aiohttp.ClientSession(timeout=timeout, connector=conn, headers=headers) as session:
        workers = []
        for i in range(args.concurrency):
            w = asyncio.create_task(worker(f"w{i+1}", queue, session, timeout, results, save_folder))
            workers.append(w)

        # push poison pills
        for _ in workers:
            await queue.put(None)

        await queue.join()
        for w in workers:
            w.cancel()
        # give cancellations time
        await asyncio.gather(*workers, return_exceptions=True)

    # Filter results to only include valid security.txt files
    valid_results = [r for r in results if r.get("status") == 200 and r.get("directives") and not r.get("error")]
    
    # write CSV - only valid security.txt files
    fieldnames = ["input", "path_checked", "status", "final_url", "error", "snippet", "directives_json"]
    with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in valid_results:
            writer.writerow({
                "input": r.get("input",""),
                "path_checked": r.get("path_checked",""),
                "status": r.get("status",""),
                "final_url": r.get("final_url",""),
                "error": r.get("error",""),
                "snippet": r.get("snippet",""),
                "directives_json": json.dumps(r.get("directives",{}), ensure_ascii=False)
            })

    # Calculate statistics
    total_entries = len(results)
    valid_security_txt = len(valid_results)  # Use filtered results count
    status_200 = sum(1 for r in results if r.get("status") == 200)
    status_404 = sum(1 for r in results if r.get("status") == 404)
    status_403 = sum(1 for r in results if r.get("status") == 403)
    status_500 = sum(1 for r in results if r.get("status") == 500)
    connection_errors = sum(1 for r in results if r.get("error") and "connect_error" in r.get("error", ""))
    timeout_errors = sum(1 for r in results if r.get("error") == "timeout")
    invalid_format = sum(1 for r in results if r.get("error") == "invalid_security_txt_format")
    
    print(f"\n=== SCAN COMPLETE ===")
    print(f"Results written to: {args.output}")
    print(f"Total entries processed: {total_entries}")
    print(f"Valid security.txt files found: {valid_security_txt}")
    print(f"Entries saved to CSV: {len(valid_results)}")
    print(f"Files saved to directory: {valid_security_txt}")
    print(f"\nStatus code breakdown:")
    print(f"  HTTP 200: {status_200}")
    print(f"  HTTP 404: {status_404}")
    print(f"  HTTP 403: {status_403}")
    print(f"  HTTP 500: {status_500}")
    print(f"\nError breakdown:")
    print(f"  Invalid security.txt format: {invalid_format}")
    print(f"  Connection errors: {connection_errors}")
    print(f"  Timeout errors: {timeout_errors}")
    print(f"  Other errors: {total_entries - status_200 - status_404 - status_403 - status_500 - connection_errors - timeout_errors - invalid_format}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Scan list of hosts/URLs for security.txt")
    p.add_argument("input", help="Input file with one host/URL per line")
    p.add_argument("--output", default="securitytxt_results.csv", help="CSV output file")
    p.add_argument("--save-files", default="", help="Directory to save found security.txt files")
    p.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests")
    p.add_argument("--timeout", type=int, default=30, help="Timeout (seconds) for each request")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header")
    p.add_argument("--insecure", action="store_true", help="Allow skipping SSL verification (not recommended)")
    args = p.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Interrupted by user")
