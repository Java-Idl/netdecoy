# NetDecoy

A no-root Android detector for **malicious captive portals** and **DNS spoofing**,
plus a self-contained **test harness** that plays the attacker so you can demo the
whole loop on one Windows laptop + one physical Android phone over USB.

- `app/` — React Native (bare CLI, no Expo) detector + a thin Kotlin native module
- `harness/` — Python attacker: a spoofing DNS resolver and a captive-portal redirector

The detector uses **differential probing**, not packet sniffing, so it needs no root:
it resolves canary domains through the network's own resolver **and** through
Cloudflare DoH, then flags divergence or private-IP answers. For portals it sends a
canary `generate_204` probe with redirects disabled and catches the `302`.

---

## 0. The physical-device reality (read this first)

You are on **Windows + WSL2 + a USB phone**. There is no emulator `-dns-server`
flag here, so the phone has to be *told* to use your laptop as its resolver. Two
things bite people:

1. **Windows Mobile Hotspot runs its own DNS on `192.168.137.1:53`** (Internet
   Connection Sharing). If you try to bind your spoofer there, port 53 is already
   taken and you'll fight ICS all night.
2. **Android Private DNS (DoT) bypasses the network resolver entirely.** If it's on,
   your spoof never lands — and the detector will correctly say SAFE. Turn it off on
   the phone for the "spoof detected" scenario.

The path below **sidesteps the ICS port-53 fight**: put the phone and laptop on the
**same normal Wi-Fi**, then manually point the phone's DNS at the laptop. No hotspot,
no ICS, port 53 is free. (If you specifically need the rogue-AP narrative, see
"Variant B" at the bottom.)

---

## 1. Harness setup

Run the harness **directly on Windows** (simplest — the scripts are pure stdlib +
`dnslib`, and you avoid WSL2↔hotspot networking). Open **PowerShell as Administrator**
(ports 53 and 80 are privileged):

```powershell
cd netdecoy\harness
pip install -r requirements.txt
```

Find your laptop's LAN IP (the phone will point DNS at this):

```powershell
ipconfig | findstr /i "IPv4"
# e.g. 192.168.1.42  — call this LAPTOP_IP
```

If port 53 is busy on Windows, it's usually the ICS "SharedAccess" service. You
don't need it for this variant:

```powershell
# only if 'OSError: address in use' on port 53
Get-Process -Id (Get-NetUDPEndpoint -LocalPort 53).OwningProcess
```

> Prefer WSL2? Put `networkingMode=mirrored` under `[wsl2]` in `C:\Users\<you>\.wslconfig`,
> run `wsl --shutdown`, and then WSL2 binds the Windows host ports directly. Run the
> two scripts with `sudo` inside WSL2. On Linux, free port 53 first with
> `sudo systemctl stop systemd-resolved`.

Point the spoofer's sinkhole and the portal's gateway at `LAPTOP_IP`:

### Option A — Interactive Web Dashboard (Recommended)

Run the unified DNS Controller with a live local web interface:

```powershell
python dns_dashboard.py
```
Open **`http://localhost:8080`** in your browser. This web page gives you:
- **1-Click Mode Toggle**: Switch between **GOOD DNS** (Clean forwarder -> SAFE in app) and **BAD DNS** (Spoofing attacker -> ALERT in app) in real time without restarting.
- **Live Traffic Feed**: Watch DNS queries from your phone stream in real time.
- **Custom Target Domains**: Add/remove hijacked domains on the fly.

### Option B — Classic CLI Harness

```powershell
# terminal 1 — rogue resolver (hijacks google.com / example.com / bank.com)
python dns_spoofer.py --sinkhole <LAPTOP_IP>

# terminal 2 — captive portal (302s every plaintext GET to a fake login)
python captive_portal.py --gateway <LAPTOP_IP>
```

---

## 2. Point the phone at the laptop

On the phone: **Settings → Network & internet → Wi-Fi → (your network) → Modify /
IP settings → Static**, then set **DNS 1 = `LAPTOP_IP`**. Keep the gateway/IP the
router already gave you.

Then **turn Private DNS off**: Settings → Network & internet → Private DNS → **Off**.

Sanity check from the laptop that the phone can reach it:

```powershell
# from the phone browser, hit http://LAPTOP_IP/  -> you should see the fake login
```

---

## 3. Build & install the detector

Prereqs on Windows: Node LTS, JDK 17, Android SDK (platform-tools), `adb`, `scrcpy`.

```powershell
# scaffold a bare RN app (once)
npx @react-native-community/cli init NetDecoy
cd NetDecoy
```

Copy this repo's app sources in:

- `app/src/*`  → `NetDecoy/src/`  (set `index.js` to `import App from './src/App'`)
- `app/android-native/NetDecoyModule.kt` and `NetDecoyPackage.kt`
  → `NetDecoy/android/app/src/main/java/com/netdecoy/`

Register the package in `MainApplication.kt` (`getPackages()` list):

```kotlin
add(NetDecoyPackage())
```

Add permissions to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

> `cleartextTraffic` — the canary probe is plain HTTP, so keep
> `android:usesCleartextTraffic="true"` on `<application>` for the demo build.

Plug in the phone (USB debugging on), then:

```powershell
adb devices          # confirm the phone shows up
scrcpy               # mirror the screen for your demo
npx react-native run-android
```

Grant the location permission when prompted (needed for the SSID readout).

---

## 4. Run the demo

1. **Baseline (SAFE).** Kill the spoofer, set phone DNS back to automatic (or point
   it at a real resolver). Tap **Scan network** → both cards green, local IPs match DoH.
2. **DNS spoofing (ALERT).** Start `dns_spoofer.py`, set phone DNS 1 = LAPTOP_IP,
   Private DNS Off. Tap **Scan** → DNS card flags `google.com` etc. as a private-IP /
   mismatch answer.
3. **Captive portal (ALERT).** Start `captive_portal.py`. Tap **Scan** → the canary
   returns `302 → http://LAPTOP_IP/login` instead of `204`, portal card goes red.

Talking point for the viva/judges: with **Private DNS ON**, step 2 returns SAFE even
with the spoofer running — that's the OS-level DoT mitigation, and your app reports
the Private-DNS state in the Network card to explain why.

---

## Variant B — true rogue AP via Windows hotspot

If you must demo the actual hotspot: enable Windows Mobile Hotspot, connect the phone
to it, and run the harness in **WSL2 mirrored mode**. ICS owns `192.168.137.1:53`, so
run the spoofer on `--port 5353` and add a Windows `netsh interface portproxy`
UDP forward from `192.168.137.1:53` → `127.0.0.1:5353`, or stop the ICS DNS. This is
fiddlier; the same-Wi-Fi static-DNS path above is what I'd demo tomorrow and keep
Variant B as a stretch goal.

---

## Ethics / scope

Everything here targets **your own devices on a network you control**, to test a
**defensive** detector. The fake landing page is clearly labelled a decoy. Don't
point the spoofer or portal at anyone else's traffic.
