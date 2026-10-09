#!/usr/bin/env python3
"""
NetDecoy test harness — malicious DNS resolver.

Answers a configurable set of target domains with a sinkhole IP (simulating a
spoofing attacker) and transparently proxies everything else to a real upstream
resolver so the device stays usable during the demo.

Run in WSL2:  sudo python3 dns_spoofer.py
Stop:         Ctrl-C
"""
import argparse
import sys

from dnslib import DNSRecord, DNSHeader, QTYPE, RR, A, RCODE
from dnslib.server import DNSServer, BaseResolver

# --- Config -----------------------------------------------------------------
SINKHOLE_IP = "127.0.0.1"           # Safe default — pass --sinkhole <LAPTOP_IP>
                                    # to point spoofed domains at your machine.
UPSTREAM = "1.1.1.1"                # real resolver for pass-through traffic
UPSTREAM_PORT = 53

# Domains to hijack. Suffix match, so "google.com" also catches
# "www.google.com", "mail.google.com", etc.
TARGET_SUFFIXES = [
    "example.com",
    "google.com",
    "bank.com",
]
# ----------------------------------------------------------------------------


def _matches(qname: str) -> bool:
    q = qname.rstrip(".").lower()
    return any(q == t or q.endswith("." + t) for t in TARGET_SUFFIXES)


class SpoofResolver(BaseResolver):
    def __init__(self, sinkhole=SINKHOLE_IP):
        self.sinkhole = sinkhole

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        if _matches(qname):
            if qtype == "A":
                print(f"[SPOOF] {qname} (A) -> {self.sinkhole}", flush=True)
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                    q=request.q,
                )
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.sinkhole), ttl=60))
                return reply
            elif qtype == "AAAA":
                print(f"[SPOOF] {qname} (AAAA) -> NODATA (forces IPv4)", flush=True)
                return DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                    q=request.q,
                )

        # --- transparent proxy to real upstream ---
        try:
            raw = request.send(UPSTREAM, UPSTREAM_PORT, timeout=3)
            proxied = DNSRecord.parse(raw)
            print(f"[pass ] {qname} ({qtype})", flush=True)
            return proxied
        except Exception as e:
            print(f"[ERR  ] upstream failed for {qname}: {e}", flush=True)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--address", default="0.0.0.0")
    ap.add_argument("--sinkhole", default=SINKHOLE_IP)
    args = ap.parse_args()

    resolver = SpoofResolver(sinkhole=args.sinkhole)
    server = DNSServer(resolver, port=args.port, address=args.address)
    print(f"DNS spoofer listening on {args.address}:{args.port}")
    print(f"  sinkhole IP : {args.sinkhole}")
    print(f"  hijacking   : {', '.join(TARGET_SUFFIXES)}")
    print(f"  upstream    : {UPSTREAM}:{UPSTREAM_PORT}")
    print("Ctrl-C to stop.\n")
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
