import { NetDecoy } from '../native/NetDecoyModule';
import { PortalProbe, PortalResult } from './types';

// Multi-vendor canaries: each is expected to return HTTP 204 No Content with 0 body.
// Captive portals and MITM proxies intercept these and return 301/302/307 redirects or 200 HTML.
const CANARIES = [
  { name: 'Google gstatic', url: 'http://connectivitycheck.gstatic.com/generate_204' },
  { name: 'Cloudflare', url: 'http://cp.cloudflare.com/generate_204' },
  { name: 'Canonical', url: 'http://connectivity-check.ubuntu.com/' },
];

export async function runPortalCheck(): Promise<PortalResult> {
  const probeResults: PortalProbe[] = [];

  for (const canary of CANARIES) {
    try {
      // Native probe uses HttpURLConnection with redirects DISABLED so we capture
      // the raw 302/redirect headers rather than following them.
      const res = await NetDecoy.probeCaptivePortal(canary.url);
      const isClean = res.status === 204 && res.bodyLen === 0;
      probeResults.push({
        name: canary.name,
        url: canary.url,
        status: res.status,
        location: res.location,
        bodyLen: res.bodyLen,
        passed: isClean,
      });
    } catch {
      probeResults.push({
        name: canary.name,
        url: canary.url,
        status: -1,
        location: null,
        bodyLen: 0,
        passed: false,
      });
    }
  }

  // Find any intercepted probes
  const intercepted = probeResults.filter((p) => {
    if (p.status === -1) return false;
    const isRedirect = p.status === 301 || p.status === 302 || p.status === 307;
    const isInterception = p.status !== 204 || p.bodyLen > 0;
    return isRedirect || isInterception;
  });

  const primary = probeResults[0] ?? { status: 204, location: null };

  if (intercepted.length > 0) {
    const suspect = intercepted[0];
    const loc = suspect.location ? ` to ${suspect.location}` : '';
    return {
      verdict: 'ALERT',
      status: suspect.status,
      location: suspect.location,
      reason: `Captive portal active: Probe [${suspect.name}] intercepted (${suspect.status})${loc}.`,
      probes: probeResults,
    };
  }

  const allFailed = probeResults.every((p) => p.status === -1);
  if (allFailed) {
    return {
      verdict: 'UNKNOWN',
      status: -1,
      location: null,
      reason: 'All connectivity probes failed to connect. Check Wi-Fi connection.',
      probes: probeResults,
    };
  }

  return {
    verdict: 'SAFE',
    status: primary.status,
    location: null,
    reason: `All canary probes (${probeResults.length}/${probeResults.length}) returned clean 204 No Content.`,
    probes: probeResults,
  };
}
