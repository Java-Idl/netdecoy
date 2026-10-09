import React, { Component, useCallback, useState } from 'react';
import {
  ActivityIndicator,
  Keyboard,
  PermissionsAndroid,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { runDnsCheck } from './detection/dnsCheck';
import { runPortalCheck } from './detection/captivePortal';
import { NetDecoy } from './native/NetDecoyModule';
import { DnsResult, NetworkStatus, PortalResult, Verdict } from './detection/types';

const COLORS: Record<Verdict, string> = {
  SAFE: '#10b981',
  ALERT: '#ef4444',
  UNKNOWN: '#f59e0b',
};

function overall(a?: Verdict, b?: Verdict): Verdict {
  if (a === 'ALERT' || b === 'ALERT') return 'ALERT';
  if (!a || !b || a === 'UNKNOWN' || b === 'UNKNOWN') return 'UNKNOWN';
  return 'SAFE';
}

function AppContent() {
  const [busy, setBusy] = useState(false);
  const [dns, setDns] = useState<DnsResult>();
  const [portal, setPortal] = useState<PortalResult>();
  const [status, setStatus] = useState<NetworkStatus>();
  const [lastScanTime, setLastScanTime] = useState<string>();
  const [customDomainInput, setCustomDomainInput] = useState('');
  const [customDomains, setCustomDomains] = useState<string[]>([]);
  const [demoMode, setDemoMode] = useState<'auto' | 'good' | 'bad'>('auto');

  const handleAddDomain = () => {
    const trimmed = customDomainInput.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (trimmed && !customDomains.includes(trimmed)) {
      setCustomDomains([...customDomains, trimmed]);
      setCustomDomainInput('');
      Keyboard.dismiss();
    }
  };

  const handleRemoveDomain = (domain: string) => {
    setCustomDomains(customDomains.filter((d) => d !== domain));
  };

  const scan = useCallback(async () => {
    if (Platform.OS === 'android') {
      try {
        await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
          {
            title: 'Location Permission',
            message: 'NetDecoy requires location access to read the Wi-Fi SSID.',
            buttonPositive: 'OK',
          },
        );
      } catch {
        // ignore
      }
    }

    setBusy(true);
    setDns(undefined);
    setPortal(undefined);
    setStatus(undefined);
    try {
      const [s, p, d] = await Promise.all([
        NetDecoy.getNetworkStatus().catch(() => undefined),
        runPortalCheck(demoMode),
        runDnsCheck(customDomains, demoMode),
      ]);
      setStatus(s);
      setPortal(p);
      setDns(d);
      setLastScanTime(new Date().toLocaleTimeString());
    } finally {
      setBusy(false);
    }
  }, [customDomains, demoMode]);

  const verdict = overall(dns?.verdict, portal?.verdict);

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <View style={styles.badgeRow}>
          <Text style={styles.shieldBadge}>🛡 NETDECOY DEFENDER</Text>
          {lastScanTime && <Text style={styles.timestampBadge}>{lastScanTime}</Text>}
        </View>
        <Text style={styles.title}>NetDecoy</Text>
        <Text style={styles.subtitle}>Autonomous Rogue Wi-Fi & DNS Spoofing Detector</Text>

        <View style={styles.demoBar}>
          <Pressable
            style={[styles.demoTab, demoMode === 'auto' && styles.demoTabActive]}
            onPress={() => setDemoMode('auto')}>
            <Text style={[styles.demoTabText, demoMode === 'auto' && styles.demoTabTextActive]}>⚡ Live Sync</Text>
          </Pressable>
          <Pressable
            style={[styles.demoTab, demoMode === 'good' && styles.demoTabGood]}
            onPress={() => setDemoMode('good')}>
            <Text style={[styles.demoTabText, demoMode === 'good' && styles.demoTabTextActive]}>🟢 SAFE</Text>
          </Pressable>
          <Pressable
            style={[styles.demoTab, demoMode === 'bad' && styles.demoTabBad]}
            onPress={() => setDemoMode('bad')}>
            <Text style={[styles.demoTabText, demoMode === 'bad' && styles.demoTabTextActive]}>🔴 SPOOF ATTACK</Text>
          </Pressable>
        </View>
      </View>

      {(dns || portal) && (
        <View style={[styles.banner, { backgroundColor: COLORS[verdict] }]}>
          <Text style={styles.bannerVerdict}>{verdict}</Text>
          <Text style={styles.bannerSub}>
            {verdict === 'SAFE'
              ? 'Network clean • Canary probes verified'
              : verdict === 'ALERT'
              ? 'Interception / Spoofing Detected'
              : 'Network status indeterminate'}
          </Text>
        </View>
      )}

      <Pressable
        style={({ pressed }) => [styles.button, busy && styles.buttonDisabled, pressed && styles.buttonPressed]}
        onPress={scan}
        disabled={busy}>
        {busy ? (
          <View style={styles.loadingRow}>
            <ActivityIndicator color="#fff" style={{ marginRight: 8 }} />
            <Text style={styles.buttonText}>Probing network...</Text>
          </View>
        ) : (
          <Text style={styles.buttonText}>Scan Network Now</Text>
        )}
      </Pressable>

      {/* Custom Target Watchlist */}
      <View style={styles.customCard}>
        <Text style={styles.customCardTitle}>Target Domain Watchlist</Text>
        <Text style={styles.customCardSub}>
          Add custom domains (e.g. your bank or VPN) to test differential resolution:
        </Text>
        <View style={styles.inputRow}>
          <TextInput
            style={styles.input}
            value={customDomainInput}
            onChangeText={setCustomDomainInput}
            placeholder="e.g. hdfcbank.com, chase.com"
            placeholderTextColor="#64748b"
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Pressable style={styles.addBtn} onPress={handleAddDomain}>
            <Text style={styles.addBtnText}>+ Add</Text>
          </Pressable>
        </View>
        {customDomains.length > 0 && (
          <View style={styles.tagWrap}>
            {customDomains.map((d) => (
              <Pressable key={d} style={styles.tag} onPress={() => handleRemoveDomain(d)}>
                <Text style={styles.tagText}>{d} ✕</Text>
              </Pressable>
            ))}
          </View>
        )}
      </View>

      {status && (
        <Card title="Network Diagnostics">
          <Row k="Wi-Fi SSID" v={status.ssid ?? 'unknown / hidden'} />
          {status.localIp && <Row k="Device IP" v={status.localIp} />}
          {status.gatewayIp && <Row k="Gateway Router" v={status.gatewayIp} />}
          <Row k="DNS Resolvers" v={status.dnsServers.join(', ') || 'none'} />
          <Row
            k="Private DNS (DoT)"
            v={status.privateDnsActive ? `Active (${status.privateDnsServer ?? 'OS resolver'})` : 'Off / Standard UDP'}
          />
          <Row k="Captive Portal Flag" v={status.hasCaptivePortalCapability ? 'Detected' : 'None'} />
          <Row k="OS Validation" v={status.validated ? 'Validated' : 'Unvalidated'} />
        </Card>
      )}

      {portal && (
        <Card title="Captive Portal Interception" verdict={portal.verdict}>
          <Text style={styles.reason}>{portal.reason}</Text>
          <Row k="Primary Canary HTTP" v={String(portal.status)} />
          {portal.location && <Row k="Redirect Target" v={portal.location} />}

          {portal.probes && portal.probes.length > 0 && (
            <View style={styles.probeContainer}>
              <Text style={styles.probeHeader}>Multi-Vendor Canary Breakdown:</Text>
              {portal.probes.map((pr) => (
                <View key={pr.name} style={styles.probeRow}>
                  <Text style={styles.probeName}>{pr.name}</Text>
                  <Text style={[styles.probeStatus, { color: pr.passed ? '#10b981' : '#ef4444' }]}>
                    {pr.status === 204 ? '204 OK' : pr.status === -1 ? 'Timed out' : `${pr.status} Intercepted`}
                  </Text>
                </View>
              ))}
            </View>
          )}
        </Card>
      )}

      {dns && (
        <Card title="DNS Integrity & Differential Probing" verdict={dns.verdict}>
          <Text style={styles.reason}>{dns.reason}</Text>
          {dns.checks.map((c) => (
            <View key={c.domain} style={styles.domainRow}>
              <View style={styles.domainHeader}>
                <Text style={styles.domain}>{c.domain}</Text>
                {c.isCustom && <Text style={styles.customBadge}>CUSTOM</Text>}
                {c.dohProvider && <Text style={styles.providerBadge}>{c.dohProvider}</Text>}
              </View>
              <Text style={styles.mono}>Local: {c.localIps.join(', ') || 'None / Failed'}</Text>
              <Text style={styles.mono}>DoH:   {c.dohIps.join(', ') || 'None / Failed'}</Text>
              {(c.diverged || c.privateAnswer) && (
                <Text style={styles.flag}>
                  {c.privateAnswer ? '⚠ Private/Bogon IP Returned' : ''}{' '}
                  {c.diverged ? '⚠ Answers Diverged vs DoH' : ''}
                </Text>
              )}
            </View>
          ))}
        </Card>
      )}
    </ScrollView>
  );
}

class ErrorBoundary extends Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  state = { hasError: false, error: undefined as Error | undefined };
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <View style={[styles.root, styles.content, { justifyContent: 'center', alignItems: 'center' }]}>
          <Text style={styles.title}>Something went wrong</Text>
          <Text style={styles.reason}>{this.state.error?.message}</Text>
          <Pressable
            style={styles.button}
            onPress={() => this.setState({ hasError: false, error: undefined })}>
            <Text style={styles.buttonText}>Retry</Text>
          </Pressable>
        </View>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <AppContent />
    </ErrorBoundary>
  );
}

function Card({ title, verdict, children }: { title: string; verdict?: Verdict; children: React.ReactNode }) {
  return (
    <View style={styles.card}>
      <View style={styles.cardHeader}>
        <Text style={styles.cardTitle}>{title}</Text>
        {verdict && <Text style={[styles.pill, { backgroundColor: COLORS[verdict] }]}>{verdict}</Text>}
      </View>
      {children}
    </View>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowKey}>{k}</Text>
      <Text style={styles.rowVal}>{v}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#070d18' },
  content: { padding: 18, paddingTop: 52, paddingBottom: 40 },
  header: { marginBottom: 18 },
  badgeRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  shieldBadge: { color: '#38bdf8', fontSize: 11, fontWeight: '800', letterSpacing: 1 },
  timestampBadge: { color: '#64748b', fontSize: 11, fontWeight: '600' },
  title: { fontSize: 32, fontWeight: '900', color: '#f8fafc', letterSpacing: -0.5 },
  subtitle: { fontSize: 13, color: '#94a3b8', marginTop: 4 },
  banner: { borderRadius: 14, paddingVertical: 16, paddingHorizontal: 20, alignItems: 'center', marginBottom: 16 },
  bannerVerdict: { color: '#fff', fontSize: 28, fontWeight: '900', letterSpacing: 2 },
  bannerSub: { color: '#f1f5f9', fontSize: 12, fontWeight: '600', marginTop: 3 },
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginBottom: 16,
    shadowColor: '#2563eb',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 4,
  },
  buttonDisabled: { opacity: 0.65 },
  buttonPressed: { opacity: 0.85, transform: [{ scale: 0.99 }] },
  loadingRow: { flexDirection: 'row', alignItems: 'center' },
  buttonText: { color: '#fff', fontWeight: '700', fontSize: 16 },
  customCard: {
    backgroundColor: '#0f172a',
    borderRadius: 12,
    padding: 14,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: '#1e293b',
  },
  customCardTitle: { color: '#e2e8f0', fontSize: 14, fontWeight: '700' },
  customCardSub: { color: '#64748b', fontSize: 12, marginTop: 2, marginBottom: 10 },
  inputRow: { flexDirection: 'row', gap: 8 },
  input: {
    flex: 1,
    backgroundColor: '#070d18',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155',
    paddingHorizontal: 12,
    paddingVertical: 8,
    color: '#f8fafc',
    fontSize: 13,
  },
  addBtn: {
    backgroundColor: '#334155',
    paddingHorizontal: 14,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
  },
  addBtnText: { color: '#f8fafc', fontWeight: '700', fontSize: 13 },
  tagWrap: { flexDirection: 'row', flexWrap: 'wrap', gap: 6, marginTop: 10 },
  tag: {
    backgroundColor: '#1e293b',
    borderRadius: 6,
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderWidth: 1,
    borderColor: '#38bdf840',
  },
  tagText: { color: '#38bdf8', fontSize: 12, fontWeight: '600' },
  card: {
    backgroundColor: '#0f172a',
    borderRadius: 14,
    padding: 16,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: '#1e293b',
  },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  cardTitle: { color: '#f8fafc', fontSize: 16, fontWeight: '800' },
  pill: {
    color: '#fff',
    fontSize: 11,
    fontWeight: '800',
    paddingHorizontal: 9,
    paddingVertical: 3,
    borderRadius: 6,
    overflow: 'hidden',
  },
  reason: { color: '#cbd5e1', fontSize: 13, marginBottom: 12, lineHeight: 18 },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 4 },
  rowKey: { color: '#94a3b8', fontSize: 13 },
  rowVal: { color: '#f1f5f9', fontSize: 13, fontWeight: '500', flexShrink: 1, textAlign: 'right', marginLeft: 12 },
  probeContainer: { marginTop: 10, paddingTop: 10, borderTopWidth: 1, borderTopColor: '#1e293b' },
  probeHeader: { color: '#64748b', fontSize: 11, fontWeight: '700', marginBottom: 6, textTransform: 'uppercase' },
  probeRow: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 3 },
  probeName: { color: '#cbd5e1', fontSize: 12 },
  probeStatus: { fontSize: 12, fontWeight: '700' },
  domainRow: { borderTopWidth: 1, borderTopColor: '#1e293b', paddingTop: 10, marginTop: 10 },
  domainHeader: { flexDirection: 'row', alignItems: 'center', marginBottom: 4 },
  domain: { color: '#fff', fontWeight: '700', fontSize: 14, marginRight: 8 },
  customBadge: {
    backgroundColor: '#3b82f630',
    color: '#60a5fa',
    fontSize: 9,
    fontWeight: '800',
    paddingHorizontal: 5,
    paddingVertical: 1,
    borderRadius: 4,
    marginRight: 6,
  },
  providerBadge: {
    backgroundColor: '#10b98120',
    color: '#34d399',
    fontSize: 9,
    fontWeight: '700',
    paddingHorizontal: 5,
    paddingVertical: 1,
    borderRadius: 4,
  },
  mono: { color: '#94a3b8', fontSize: 12, fontFamily: 'monospace', marginTop: 1 },
  flag: { color: '#f87171', fontSize: 12, fontWeight: '600', marginTop: 4 },
  demoBar: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 12,
    backgroundColor: '#0f172a',
    padding: 4,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#1e293b',
  },
  demoTab: {
    flex: 1,
    paddingVertical: 8,
    borderRadius: 7,
    alignItems: 'center',
    justifyContent: 'center',
  },
  demoTabActive: {
    backgroundColor: '#1e293b',
  },
  demoTabGood: {
    backgroundColor: '#065f46',
  },
  demoTabBad: {
    backgroundColor: '#7f1d1d',
  },
  demoTabText: {
    color: '#94a3b8',
    fontSize: 11,
    fontWeight: '700',
  },
  demoTabTextActive: {
    color: '#f8fafc',
    fontWeight: '800',
  },
});
