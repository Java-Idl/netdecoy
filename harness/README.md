# NetDecoy harness

Two attacker roles for testing the detector. See the top-level `README.md` for the
full physical-device runbook. Both need admin/root for ports 53/80.

```bash
pip install -r requirements.txt

# rogue resolver — hijacks TARGET_SUFFIXES to the sinkhole, proxies the rest
python dns_spoofer.py --sinkhole <LAPTOP_IP>
python dns_spoofer.py --port 5353 --sinkhole <LAPTOP_IP>   # non-privileged

# captive portal — 302s every plaintext GET to a fake login page
python captive_portal.py --gateway <LAPTOP_IP>
python captive_portal.py --port 8080 --gateway <LAPTOP_IP> # non-privileged
```

Verify locally before touching the phone:

```bash
# spoof hits (expect the sinkhole IP)
python -c "from dnslib import DNSRecord; print([str(r.rdata) for r in DNSRecord.parse(DNSRecord.question('google.com').send('127.0.0.1',53)).rr])"
# portal hits (expect 302 + Location)
curl -sD - -o /dev/null http://127.0.0.1/generate_204
```

Edit in `dns_spoofer.py`: `TARGET_SUFFIXES` (what to hijack), `UPSTREAM` (real resolver).
