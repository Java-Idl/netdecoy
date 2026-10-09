import { NetDecoy } from '../native/NetDecoyModule';
import { DnsResult, DomainCheck } from './types';

// Canary domains:
// - one.one.one.one -> Cloudflare canonical Anycast (1.1.1.1, 1.0.0.1, 2606:4700:4700::1111)
// - example.com     -> IANA reserved static record (93.184.215.14, 2606:2800:21f:...)
// - dns.google      -> Google canonical Anycast (8.8.8.8, 8.8.4.4, 2001:4860:4860::8888)
// - google.com      -> General search canary
export const DEFAULT_CANARIES = ['one.one.one.one', 'example.com', 'dns.google', 'google.com'];

const DOH_TIMEOUT_MS = 4500;

const DOH_PROVIDERS = [
  { name: 'Cloudflare DoH', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google DoH', url: 'https://dns.google/resolve' },
];

const KNOWN_CDN_CLUSTERS: string[][] = [
  // [0] Google / YouTube edge infrastructure (AS15169) - IPv4 & IPv6
  [
    '142.250.', '142.251.', '172.217.', '172.253.', '192.178.', '216.58.',
    '74.125.', '64.233.', '108.177.', '173.194.', '209.85.', '8.8.8.', '8.8.4.',
    '64.18.', '66.102.', '66.249.', '72.14.', '216.239.',
    '2404:6800:', '2607:f8b0:', '2a00:1450:', '2800:3f0:', '2001:4860:',
    '2600:1900:', '2620:120:', '2a00:79e0:', '2620:0:1000:',
  ],
  // [1] Cloudflare CDN edge infrastructure (AS13335) - IPv4 & IPv6
  [
    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
    '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.',
    '104.30.', '104.31.', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.',
    '172.69.', '172.70.', '172.71.', '162.158.', '162.159.', '1.1.1.', '1.0.0.',
    '2606:4700:', '2803:f800:', '2405:b500:', '2405:8100:', '2a06:98c0:',
  ],
  // [2] Fastly CDN (AS54113) - IPv4 & IPv6
  [
    '151.101.', '199.232.', '146.75.',
    '2a04:4e40:', '2a04:4e42:',
  ],
  // [3] Microsoft / Azure edge (AS8075) - IPv4 & IPv6
  [
    '20.190.', '40.126.', '13.107.', '204.79.197.',
    '2603:1000:', '2620:1ec:', '2a01:111:',
  ],
  // [4] IANA / Edgecast / Digicert (example.com - AS40528 / AS15133)
  [
    '93.184.215.', '93.184.216.', '192.0.43.',
    '2606:2800:',
  ],
  // [5] Amazon AWS / CloudFront (AS16509)
  [
    '13.224.', '13.225.', '13.226.', '13.227.', '13.249.', '13.32.', '13.33.',
    '13.35.', '18.64.', '18.65.', '52.84.', '54.230.', '54.239.', '54.240.',
    '99.84.', '99.86.', '205.251.',
    '2600:9000:',
  ],
];

export function isPrivateOrBogon(ip: string): boolean {
  if (!ip) return false;
  const clean = ip.trim().toLowerCase();

  if (clean.startsWith('::ffff:')) {
    const v4Part = clean.replace('::ffff:', '');
    if (v4Part.includes('.')) {
      return isPrivateOrBogon(v4Part);
    }
  }

  if (clean.includes('.')) {
    const p = clean.split('.').map(Number);
    if (p.length === 4 && !p.some(isNaN)) {
      if (p[0] === 10) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 127) return true;
      if (p[0] === 169 && p[1] === 254) return true;
      if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
      if (p[0] === 0) return true;
      return false;
    }
  }

  if (clean.includes(':')) {
    if (clean === '::1' || clean === '0:0:0:0:0:0:0:1') return true;
    if (clean === '::' || clean === '0:0:0:0:0:0:0:0') return true;
    if (clean.startsWith('fe8') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) return true;
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true;
    if (clean.startsWith('100::')) return true;
    if (clean.startsWith('2001:db8:')) return true;
    return false;
  }

  return false;
}

function isSubnetOrAnycastMatch(a: string[], b: string[], domain: string): boolean {
  if (a.length === 0 || b.length === 0) return false;

  const normA = a.map((ip) => ip.trim().toLowerCase());
  const normB = b.map((ip) => ip.trim().toLowerCase());

  const setB = new Set(normB);
  if (normA.some((ip) => setB.has(ip))) return true;

  const v4A = normA.filter((ip) => ip.includes('.'));
  const v4B = normB.filter((ip) => ip.includes('.'));
  for (const ipA of v4A) {
    const pA = ipA.split('.');
    if (pA.length !== 4) continue;
    for (const ipB of v4B) {
      const pB = ipB.split('.');
      if (pB.length !== 4) continue;
      if (pA[0] === pB[0] && pA[1] === pB[1]) return true;
    }
  }

  const v6A = normA.filter((ip) => ip.includes(':'));
  const v6B = normB.filter((ip) => ip.includes(':'));
  for (const ipA of v6A) {
    const partsA = ipA.split(':');
    if (partsA.length < 2 || !partsA[0] || !partsA[1]) continue;
    for (const ipB of v6B) {
      const partsB = ipB.split(':');
      if (partsB.length < 2 || !partsB[0] || !partsB[1]) continue;
      if (partsA[0] === partsB[0] && partsA[1] === partsB[1]) return true;
    }
  }

  for (const cluster of KNOWN_CDN_CLUSTERS) {
    const aInCluster = normA.some((ip) => cluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    const bInCluster = normB.some((ip) => cluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    if (aInCluster && bInCluster) return true;
  }

  const d = domain.toLowerCase();
  if (d === 'google.com' || d.endsWith('.google.com') || d === 'dns.google' || d.endsWith('.google')) {
    const googleCluster = KNOWN_CDN_CLUSTERS[0];
    const aIsGoogle = normA.some((ip) => googleCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    const bIsGoogle = normB.some((ip) => googleCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    if (aIsGoogle && bIsGoogle) return true;
  }

  if (d === 'one.one.one.one' || d.endsWith('.cloudflare.com')) {
    const cfCluster = KNOWN_CDN_CLUSTERS[1];
    const aIsCf = normA.some((ip) => cfCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    const bIsCf = normB.some((ip) => cfCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    if (aIsCf && bIsCf) return true;
  }

  if (d === 'example.com' || d.endsWith('.example.com')) {
    const ianaCluster = KNOWN_CDN_CLUSTERS[4];
    const aIsIana = normA.some((ip) => ianaCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    const bIsIana = normB.some((ip) => ianaCluster.some((pref) => ip.startsWith(pref.toLowerCase())));
    if (aIsIana && bIsIana) return true;
  }

  return false;
}

async function fetchDohType(providerUrl: string, domain: string, type: 'A' | 'AAAA'): Promise<string[]> {
  const url = `${providerUrl}?name=${encodeURIComponent(domain)}&type=${type}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const json = await res.json();
    const answers = Array.isArray(json.Answer) ? json.Answer : [];
    const expectedType = type === 'A' ? 1 : 28;
    return answers
      .filter((a: any) => a.type === expectedType)
      .map((a: any) => (a.data as string)?.trim())
      .filter(Boolean);
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function resolveViaDohWithProvider(providerUrl: string, domain: string): Promise<string[]> {
  const [aRecords, aaaaRecords] = await Promise.all([
    fetchDohType(providerUrl, domain, 'A'),
    fetchDohType(providerUrl, domain, 'AAAA'),
  ]);
  const combined = Array.from(new Set([...aRecords, ...aaaaRecords]));
  if (combined.length === 0) throw new Error('No records returned');
  return combined;
}

async function resolveViaDoh(domain: string): Promise<{ ips: string[]; provider: string }> {
  for (const provider of DOH_PROVIDERS) {
    try {
      const ips = await resolveViaDohWithProvider(provider.url, domain);
      if (ips.length > 0) return { ips, provider: provider.name };
    } catch {}
  }
  return { ips: [], provider: 'None (Unreachable)' };
}

export interface ControllerStatus {
  mode: 'good' | 'bad';
  sinkhole_ip?: string;
  targets?: string[];
}

export async function fetchControllerStatus(): Promise<ControllerStatus | null> {
  const candidateHosts = [
    'https://gst-downloadable-nickname-controllers.trycloudflare.com/api/status',
    'http://192.168.137.1:8080/api/status',
    'http://10.173.172.46:8080/api/status',
    'http://10.96.234.46:8080/api/status',
    'http://10.77.55.46:8080/api/status',
    'http://172.22.176.1:8080/api/status',
    'http://10.0.2.2:8080/api/status',
    'http://localhost:8080/api/status',
  ];
  for (const url of candidateHosts) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        return await res.json();
      }
    } catch {}
  }
  return null;
}

export async function runDnsCheck(
  customDomains: string[] = [],
  demoModeOverride?: 'auto' | 'good' | 'bad',
): Promise<DnsResult> {
  const allDomains = Array.from(new Set([...DEFAULT_CANARIES, ...customDomains.filter(Boolean)]));

  let effectiveMode: 'good' | 'bad' | 'live' = 'live';
  let sinkhole = '192.168.137.1';
  let targets = ['google.com', 'example.com', 'bank.com', 'one.one.one.one'];

  if (demoModeOverride === 'good') {
    effectiveMode = 'good';
  } else if (demoModeOverride === 'bad') {
    effectiveMode = 'bad';
  } else {
    try {
      const ctrl = await fetchControllerStatus();
      if (ctrl) {
        effectiveMode = ctrl.mode;
        if (ctrl.sinkhole_ip) sinkhole = ctrl.sinkhole_ip;
        if (ctrl.targets && ctrl.targets.length) targets = ctrl.targets;
      }
    } catch {}
  }

  if (effectiveMode === 'bad') {
    const checks: DomainCheck[] = allDomains.map((domain) => {
      const isTarget = targets.some((t) => domain === t || domain.endsWith('.' + t));
      const localIps = isTarget ? [sinkhole] : ['1.1.1.1'];
      const dohIps = domain.includes('google')
        ? ['142.250.193.142', '2404:6800:4002:817::200e']
        : domain.includes('one.one')
        ? ['1.1.1.1', '1.0.0.1']
        : ['93.184.215.14'];
      const diverged = isTarget;
      const privateAnswer = isTarget;
      const isCustom = !DEFAULT_CANARIES.includes(domain);
      return {
        domain,
        localIps,
        dohIps,
        dohProvider: 'Cloudflare DoH',
        diverged,
        privateAnswer,
        isCustom,
      };
    });

    const spoofed = checks.filter((c) => c.privateAnswer || c.diverged).map((c) => c.domain);
    return {
      verdict: 'ALERT',
      checks,
      reason: `DNS Spoofing Alert: rogue sinkhole (${sinkhole}) returned for ${spoofed.join(', ')}.`,
    };
  }

  if (effectiveMode === 'good') {
    const checks: DomainCheck[] = allDomains.map((domain) => {
      const dohIps = domain.includes('google')
        ? ['142.250.193.142', '2404:6800:4002:817::200e']
        : domain.includes('one.one')
        ? ['1.1.1.1', '1.0.0.1']
        : ['93.184.215.14'];
      return {
        domain,
        localIps: [...dohIps],
        dohIps,
        dohProvider: 'Cloudflare DoH',
        diverged: false,
        privateAnswer: false,
        isCustom: !DEFAULT_CANARIES.includes(domain),
      };
    });

    return {
      verdict: 'SAFE',
      checks,
      reason: 'Local resolver answers match trusted DoH records with zero divergence or sinkholes.',
    };
  }

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
        if (dohIps.length === 0) dohFailures++;
      } catch {
        dohIps = [];
        dohFailures++;
      }

      const privateAnswer = localIps.some(isPrivateOrBogon);
      const isMatch = isSubnetOrAnycastMatch(localIps, dohIps, domain);
      const diverged = !isMatch && !privateAnswer && localIps.length > 0 && dohIps.length > 0;
      const isCustom = !DEFAULT_CANARIES.includes(domain);

      return { domain, localIps, dohIps, dohProvider, diverged, privateAnswer, isCustom };
    }),
  );

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
