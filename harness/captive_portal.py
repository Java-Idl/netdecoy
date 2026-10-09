#!/usr/bin/env python3
"""
NetDecoy test harness — malicious captive portal.

Intercepts every plaintext HTTP request and 302-redirects it to a fake
"Wi-Fi login" landing page. This is what your detector's canary probe
(http://connectivitycheck.gstatic.com/generate_204) should catch: instead of
the expected 204 No Content, it receives a 302 to an attacker-controlled URL.

Run in WSL2:  sudo python3 captive_portal.py
              (port 80 needs root, or use --port 8000 and adjust probes)
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

LANDING = Path(__file__).parent / "landing" / "login.html"


class CaptivePortalHandler(BaseHTTPRequestHandler):
    server_version = "AP-Gateway/1.0"        # deliberately NOT gstatic/Google
    portal_host = "127.0.0.1"                # safe default — pass --gateway <LAPTOP_IP>
    portal_port = 80

    def _redirect(self):
        target = f"http://{self.portal_host}:{self.portal_port}/login"
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve_landing(self):
        try:
            body = LANDING.read_bytes()
        except FileNotFoundError:
            body = b"<h1>Sign in to Wi-Fi</h1><form><input placeholder='email'></form>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        print(f"[GET ] {self.headers.get('Host','?')}{self.path}", flush=True)
        if self.path.startswith("/login"):
            self._serve_landing()
        else:
            # Every other path (including /generate_204) gets intercepted.
            self._redirect()

    def do_POST(self):
        """Handle fake login form submissions — log and acknowledge."""
        print(f"[POST] {self.headers.get('Host','?')}{self.path}", flush=True)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        fields = parse_qs(body)
        print(f"  [CAPTURED] {fields}", flush=True)

        msg = b"<h1>Connected!</h1><p>Redirecting&hellip;</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

    def do_HEAD(self):
        print(f"[HEAD] {self.headers.get('Host','?')}{self.path}", flush=True)
        self._redirect()

    def log_message(self, *args):
        pass  # we do our own logging above


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--gateway", default="127.0.0.1",
                    help="IP the landing page lives on (pass your laptop LAN IP)")
    args = ap.parse_args()

    CaptivePortalHandler.portal_host = args.gateway
    CaptivePortalHandler.portal_port = args.port

    srv = ThreadingHTTPServer((args.host, args.port), CaptivePortalHandler)
    print(f"Captive portal listening on {args.host}:{args.port}")
    print(f"  landing page: http://{args.gateway}:{args.port}/login")
    print("Ctrl-C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        srv.shutdown()


if __name__ == "__main__":
    main()
