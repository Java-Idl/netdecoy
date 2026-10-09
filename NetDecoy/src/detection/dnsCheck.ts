import { NetDecoy } from '../native/NetDecoyModule';
import { DnsResult, DomainCheck } from './types';

// Canary domains:
// - one.one.one.one -> Cloudflare canonical Anycast (1.1.1.1, 1.0.0.1)
// - example.com     -> IANA reserved static record (93.184.215.14 / 93.184.216.34)
// - dns.google      -> Google canonical Anycast (8.8.8.8, 8.8.4.4)
// - google.com      -> General search canary
export const DEFAULT_CANARIES = ['one.one.one.one', 'example.com', 'dns.google', 'google.com'];

const DOH_TIMEOUT_MS = 4500;

const DOH_PROVIDERS = [
  { name: 'Cloudflare DoH', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google DoH', url: 'https://dns.google/resolve' },
];

export function isPrivateOrBogon(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(isNaN)) return false;
  if (p[0] === 10) return true;                                // 10.0.0.0/8
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;  // 172.16.0.0/12
  if (p[0] === 192 && p[1] === 168) return true;              // 192.168.0.0/16
  if (p[0] === 127) return true;                               // loopback 127.0.0.0/8
  if (p[0] === 169 && p[1] === 254) return true;               // link-local (APIPA)
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;  // CGNAT (100.64.0.0/10)
  if (p[0] === 0) return true;                                 // 0.0.0.0/8 sinkhole
  return false;
}

/** Check if two IP sets share an exact IP or belong to the same CDN /16 edge cluster */
function isSubnetOrAnycastMatch(a: string[], b: string[]): boolean {
  if (a.length === 0 || b.length === 0) return false;

  // 1. Exact IP match
  const setB = new Set(b);
  if (a.some((ip) => setB.has(ip))) return true;

  // 2. Class B subnet match (/16) for public CDN clusters (e.g. 142.250.x.x Google edge nodes)
  for (const ipA of a) {
    const pA = ipA.split('.');
    if (pA.length !== 4) continue;
    for (const ipB of b) {
      const pB = ipB.split('.');
      if (pB.length !== 4) continue;
      if (pA[0] === pB[0] && pA[1] === pB[1]) {
        return true;
      }
    }
  }

  return false;
}

async function resolveViaDohWithProvider(providerUrl: string, domain: string): Promise<string[]> {
  const url = `${providerUrl}?name=${encodeURIComponent(domain)}&type=A`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    const answers = Array.isArray(json.Answer) ? json.Answer : [];
    return answers
      .filter((a: any) => a.type === 1) // type 1 = A record
      .map((a: any) => a.data as string)
      .filter(Boolean);
  } finally {
    clearTimeout(timer);
  }
}

/** Resolves domain via trusted DoH, falling back between Cloudflare and Google. */
async function resolveViaDoh(domain: string): Promise<{ ips: string[]; provider: string }> {
  for (const provider of DOH_PROVIDERS) {
    try {
      const ips = await resolveViaDohWithProvider(provider.url, domain);
      if (ips.length > 0) {
        return { ips, provider: provider.name };
      }
    } catch {
      // try next provider
    }
  }
  return { ips: [], provider: 'None (Unreachable)' };
}

export async function runDnsCheck(customDomains: string[] = []): Promise<DnsResult> {
  const allDomains = Array.from(new Set([...DEFAULT_CANARIES, ...customDomains.filter(Boolean)]));
  let dohFailures = 0;

  const checks: DomainCheck[] = await Promise.all(
    allDomains.map(async (domain) => {
      let localIps: string[] = [];
      let dohIps: string[] = [];
      let dohProvider = 'Cloudflare DoH';

      try {
        // Queries Android's real active network DHCP resolver directly
        localIps = await NetDecoy.resolveViaNetwork(domain);
      } catch {
        localIps = [];
      }

      try {
        const dohRes = await resolveViaDoh(domain);
        dohIps = dohRes.ips;
        dohProvider = dohRes.provider;
        if (dohIps.length === 0) {
          dohFailures++;
        }
      } catch {
        dohIps = [];
        dohFailures++;
      }

      const privateAnswer = localIps.some(isPrivateOrBogon);
      const isMatch = isSubnetOrAnycastMatch(localIps, dohIps);
      const diverged = !isMatch && !privateAnswer && localIps.length > 0 && dohIps.length > 0;
      const isCustom = !DEFAULT_CANARIES.includes(domain);

      return { domain, localIps, dohIps, dohProvider, diverged, privateAnswer, isCustom };
    }),
  );

  // If DoH is completely blocked or failed across all domains
  if (dohFailures === allDomains.length) {
    const privateFound = checks.some((c) => c.privateAnswer);
    if (privateFound) {
      return {
        verdict: 'ALERT',
        checks,
        reason: 'Local DNS returned private/sinkhole IP addresses. DoH was also unreachable.',
      };
    }
    return {
      verdict: 'UNKNOWN',
      checks,
      reason: 'Could not reach DoH resolvers (Cloudflare/Google). Verify internet access.',
    };
  }

  const spoofed = checks.filter((c) => c.privateAnswer || c.diverged);

  if (spoofed.length === 0) {
    return {
      verdict: 'SAFE',
      checks,
      reason: 'Local resolver answers match trusted DoH records with zero divergence or sinkholes.',
    };
  }

  const priv = spoofed.filter((c) => c.privateAnswer).map((c) => c.domain);
  const div = spoofed.filter((c) => c.diverged && !c.privateAnswer).map((c) => c.domain);
  const parts: string[] = [];
  if (priv.length) parts.push(`private/bogon IP answers for ${priv.join(', ')}`);
  if (div.length) parts.push(`unrecognized IP divergence for ${div.join(', ')}`);

  return {
    verdict: 'ALERT',
    checks,
    reason: `DNS Spoofing Alert: ${parts.join('; ')}.`,
  };
}
