#!/usr/bin/env python3
"""
   ___           _         ___ _           _       
  / _ \ _  _ ___| |_ __ _ / __| |_  ___ __| |___ _ 
 | (_) | || / _ \  _/ _` | (__| ' \/ -_) _| / / '_|
  \__\_\\_,_\___/\__\__,_|\___|_||_\___\__|_\_\_|  
IMAP quota checker with optional SSL verification bypass.

Usage:
  # Normal (verify certs)
  python3 quotacheckr.py --server mail.example.tld --user you@domain --password secret

  # Bypass cert verification (INSECURE — for testing only)
  python3 quotacheckr.py --server mail.example.tld --user you@domain --password secret --insecure

  # Use STARTTLS on port 143 (verify by default, or use --insecure)
  python3 quotacheckr.py --server mail.example.tld --port 143 --starttls --user ... --password ... [--insecure]
"""
import imaplib
import ssl
import re
import argparse
import sys

def create_ssl_context(insecure: bool):
    if insecure:
        # WARNING: disables cert verification (insecure)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    else:
        return ssl.create_default_context()

def get_quota_via_imap(imap):
    # send raw GETQUOTAROOT INBOX and parse untagged QUOTA response
    typ, data = imap._simple_command('GETQUOTAROOT', 'INBOX')
    if typ != 'OK':
        return None, "Server didn't accept GETQUOTAROOT (no QUOTA support)"
    try:
        typ2, resp = imap._untagged_response(typ, data, 'QUOTA')
    except Exception:
        resp = None
    if not resp:
        return None, "No QUOTA response"
    joined = b" ".join(resp).decode(errors="ignore")
    m = re.search(r'STORAGE\s+(\d+)\s+(\d+)', joined)
    if not m:
        return None, f"Failed parse QUOTA: {joined}"
    used_kb = int(m.group(1))
    limit_kb = int(m.group(2))
    return (used_kb, limit_kb), None

def human(n_kb):
    mb = n_kb / 1024.0
    return f"{mb:.2f} MB"

def main():
    p = argparse.ArgumentParser(description="IMAP quota checker (optional insecure TLS bypass)")
    p.add_argument("--server", required=True)
    p.add_argument("--port", type=int, default=993)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (INSECURE)")
    p.add_argument("--starttls", action="store_true", help="Use STARTTLS (connect plain then upgrade) - typically port 143")
    args = p.parse_args()

    ctx = create_ssl_context(args.insecure)

    try:
        if args.starttls:
            # plain connect then STARTTLS
            imap = imaplib.IMAP4(args.server, args.port)
            # upgrade to TLS
            imap.starttls(ssl_context=ctx)
        else:
            imap = imaplib.IMAP4_SSL(args.server, args.port, ssl_context=ctx)
    except Exception as e:
        print(f"[ERROR] connection failed: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        imap.login(args.user, args.password)
    except imaplib.IMAP4.error as e:
        print(f"[ERROR] login failed: {e}", file=sys.stderr)
        try: imap.logout()
        except: pass
        sys.exit(3)

    quota, err = get_quota_via_imap(imap)
    if quota:
        used_kb, limit_kb = quota
        pct = (used_kb / limit_kb * 100) if limit_kb > 0 else 0
        print(f"Server     : {args.server}:{args.port} (starttls={args.starttls})")
        print(f"User       : {args.user}")
        print(f"Used       : {used_kb} KB  ({human(used_kb)})")
        print(f"Limit      : {limit_kb} KB  ({human(limit_kb)})")
        print(f"Percent    : {pct:.1f}%")
        if args.insecure:
            print("⚠️  Warning: SSL verification DISABLED (insecure)")
    else:
        print(f"[WARN] Could not retrieve quota: {err}")
        if args.insecure:
            print("⚠️  Note: running with --insecure; consider enabling certificate verification after fixing server certs.")
    try:
        imap.logout()
    except:
        pass

if __name__ == "__main__":
    main()
