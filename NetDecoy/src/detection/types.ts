export type Verdict = 'SAFE' | 'ALERT' | 'UNKNOWN';

export interface DomainCheck {
  domain: string;
  localIps: string[];     // what the DHCP-assigned resolver returned
  dohIps: string[];       // what trusted DoH returned
  dohProvider?: string;   // provider name (Cloudflare, Google)
  diverged: boolean;      // IP sets share nothing
  privateAnswer: boolean; // local resolver handed back an RFC1918/bogon address
  isCustom?: boolean;
}

export interface DnsResult {
  verdict: Verdict;
  checks: DomainCheck[];
  reason: string;
}

export interface PortalProbe {
  name: string;
  url: string;
  status: number;
  location: string | null;
  bodyLen: number;
  passed: boolean;
}

export interface PortalResult {
  verdict: Verdict;
  status: number;         // Primary canary HTTP status
  location: string | null;
  reason: string;
  probes?: PortalProbe[];
}

export interface NetworkStatus {
  dnsServers: string[];
  privateDnsActive: boolean;
  privateDnsServer: string | null;
  hasCaptivePortalCapability: boolean;
  validated: boolean;
  ssid: string | null;
  gatewayIp?: string | null;
  localIp?: string | null;
}
