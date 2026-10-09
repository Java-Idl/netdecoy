import { NetDecoy } from '../native/NetDecoyModule';
import { DnsResult, DomainCheck } from './types';

// Default canary domains: widely deployed, stable records.
export const DEFAULT_CANARIES = ['google.com', 'cloudflare.com', 'example.com'];

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

function disjoint(a: string[], b: string[]): boolean {
  if (a.length === 0 || b.length === 0) return false;
  const setB = new Set(b);
  return !a.some((ip) => setB.has(ip));
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
      const diverged = disjoint(localIps, dohIps);
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
      reason: 'Local network resolver matches trusted encrypted DoH records on all tested canaries.',
    };
  }

  const priv = spoofed.filter((c) => c.privateAnswer).map((c) => c.domain);
  const div = spoofed.filter((c) => c.diverged && !c.privateAnswer).map((c) => c.domain);
  const parts: string[] = [];
  if (priv.length) parts.push(`private/bogon IP answers for ${priv.join(', ')}`);
  if (div.length) parts.push(`IP divergence vs DoH for ${div.join(', ')}`);

  return {
    verdict: 'ALERT',
    checks,
    reason: `DNS Spoofing Detected: ${parts.join('; ')}.`,
  };
}
