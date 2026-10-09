#!/usr/bin/env python3
"""
NetDecoy test harness — Benign / Clean DNS Resolver (Mock Good DNS).

Answers DNS queries truthfully without any spoofing or manipulation,
demonstrating that NetDecoy outputs SAFE (Green) with ZERO false positives
when connected to a legitimate resolver.

Run in PowerShell (Admin):
    python mock_good_dns.py
"""
import argparse
import sys

from dnslib import DNSRecord, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver

# Upstream resolver for real, clean lookups
UPSTREAM = "1.1.1.1"
UPSTREAM_PORT = 53

# Canonical truthful answers for standard canaries
CANONICAL_RECORDS = {
    "example.com": ["93.184.215.14"],
    "one.one.one.one": ["1.1.1.1", "1.0.0.1"],
    "dns.google": ["8.8.8.8", "8.8.4.4"],
}


class CleanMockResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        # Transparently query real trusted upstream DNS (Cloudflare 1.1.1.1)
        try:
            raw = request.send(UPSTREAM, UPSTREAM_PORT, timeout=3)
            reply = DNSRecord.parse(raw)
            answers = [str(r.rdata) for r in reply.rr if r.rtype == 1]
            print(f"[CLEAN DNS] {qname} ({qtype}) -> {', '.join(answers) or 'OK'} [VERIFIED SAFE]", flush=True)
            return reply
        except Exception as e:
            print(f"[ERR] Upstream query failed for {qname}: {e}", flush=True)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    ap = argparse.ArgumentParser(description="NetDecoy Clean Mock DNS Resolver (No Spoofing)")
    ap.add_argument("--port", type=int, default=53, help="Port to bind (default: 53)")
    ap.add_argument("--address", default="0.0.0.0", help="Address to bind (default: 0.0.0.0)")
    args = ap.parse_args()

    resolver = CleanMockResolver()
    server = DNSServer(resolver, port=args.port, address=args.address)

    print("=" * 65)
    print("  NetDecoy Mock Clean DNS Resolver (Zero False Positives)")
    print("=" * 65)
    print(f"Listening on : {args.address}:{args.port}")
    print(f"Mode         : BENIGN (Non-spoofing truthful forwarder)")
    print(f"Upstream     : {UPSTREAM}:{UPSTREAM_PORT}")
    print("Expected NetDecoy Verdict: >>> SAFE (GREEN) <<<\n")
    print("Press Ctrl-C to stop.\n")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nStopping Clean Mock DNS Server.")
        server.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
