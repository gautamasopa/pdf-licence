#!/usr/bin/env python3
"""
issue_key.py — Issue a new licence key via the admin API.

Usage:
    python issue_key.py --server https://your-app.up.railway.app \
                        --admin-key YOUR_ADMIN_KEY \
                        --name "Customer Name" \
                        [--seats 1]

The script generates a PHIL-MMYY-XXXX key automatically,
then calls /admin/issue to register it.

You can also pass --key to specify a key explicitly.
"""

import argparse
import random
import string
import sys
import time
import requests


def generate_key() -> str:
    """PHIL-MMYY-XXXX  e.g. PHIL-0525-K7R2"""
    mm   = time.strftime("%m")
    yy   = time.strftime("%y")
    rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"PHIL-{mm}{yy}-{rand}"


def main():
    parser = argparse.ArgumentParser(description="Issue a PDF Squeeze licence key")
    parser.add_argument("--server",    required=True,  help="Base URL of licence server")
    parser.add_argument("--admin-key", required=True,  help="ADMIN_KEY value")
    parser.add_argument("--name",      required=True,  help="Customer name")
    parser.add_argument("--seats",     type=int, default=1, help="Number of machines (default 1)")
    parser.add_argument("--key",       default="",     help="Override key (auto-generated if omitted)")
    args = parser.parse_args()

    key = args.key.strip().upper() or generate_key()
    url = args.server.rstrip("/") + "/admin/issue"

    print(f"Issuing key: {key}")
    print(f"  Issued to: {args.name}")
    print(f"  Seats:     {args.seats}")
    print(f"  Server:    {url}")
    print()

    try:
        resp = requests.post(
            url,
            json={"key": key, "issued_to": args.name, "seats": args.seats},
            headers={"X-Admin-Key": args.admin_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 201:
        data = resp.json()
        print("✓ Key issued successfully")
        print(f"  Key:       {data['key']}")
        print(f"  Issued to: {data['issued_to']}")
        print(f"  Seats:     {data['seats']}")
    elif resp.status_code == 409:
        print("ERROR: Key already exists", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"ERROR {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()