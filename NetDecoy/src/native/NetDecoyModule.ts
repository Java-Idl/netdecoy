import { NativeModules } from 'react-native';
import { NetworkStatus } from '../detection/types';

interface PortalProbe {
  status: number;
  location: string | null;
  bodyLen: number;
}

interface NetDecoyNative {
  /** Resolve `host` using the active network's DHCP-assigned resolver. */
  resolveViaNetwork(host: string): Promise<string[]>;
  /** GET `url` with redirects disabled; report raw status/location/body size. */
  probeCaptivePortal(url: string): Promise<PortalProbe>;
  /** Current network's DNS config, Private-DNS state, and portal capability. */
  getNetworkStatus(): Promise<NetworkStatus>;
}

// Falls back to a clear error if the native module wasn't linked.
export const NetDecoy: NetDecoyNative =
  (NativeModules.NetDecoy as NetDecoyNative) ??
  new Proxy({} as NetDecoyNative, {
    get() {
      return async () => {
        throw new Error(
          'NetDecoy native module not linked. Rebuild the Android app after adding the Kotlin module.',
        );
      };
    },
  });
