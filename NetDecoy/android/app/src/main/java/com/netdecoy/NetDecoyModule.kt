package com.netdecoy

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

class NetDecoyModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "NetDecoy"

    private fun cm(): ConnectivityManager =
        reactContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    /**
     * Resolve [host] using the ACTIVE network's resolver specifically. On a
     * spoofed hotspot this returns whatever the rogue DNS handed back, which the
     * JS layer then compares against Cloudflare DoH.
     */
    @ReactMethod
    fun resolveViaNetwork(host: String, promise: Promise) {
        Thread {
            try {
                val network = cm().activeNetwork
                    ?: throw IllegalStateException("no active network")
                val addrs: Array<InetAddress> = network.getAllByName(host)
                val out = Arguments.createArray()
                addrs.forEach { out.pushString(it.hostAddress) }
                promise.resolve(out)
            } catch (e: Exception) {
                promise.reject("RESOLVE_FAILED", e.message, e)
            }
        }.start()
    }

    /**
     * GET [url] with redirect following DISABLED so a captive portal's 302 is
     * visible instead of being auto-followed. Reports status, Location header,
     * and body length (a clean canary is 204 with a 0-byte body).
     */
    @ReactMethod
    fun probeCaptivePortal(url: String, promise: Promise) {
        Thread {
            var conn: HttpURLConnection? = null
            try {
                val network = cm().activeNetwork
                // Bind the socket to the active network so the probe really goes
                // over the Wi-Fi under test, not some other interface.
                conn = if (network != null) {
                    network.openConnection(URL(url)) as HttpURLConnection
                } else {
                    URL(url).openConnection() as HttpURLConnection
                }
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.requestMethod = "GET"

                val status = conn.responseCode
                val location = conn.getHeaderField("Location")
                val stream = if (status in 200..399) conn.inputStream else conn.errorStream
                val bodyLen = stream?.readBytes()?.size ?: 0

                val result = Arguments.createMap().apply {
                    putInt("status", status)
                    if (location != null) putString("location", location) else putNull("location")
                    putInt("bodyLen", bodyLen)
                }
                promise.resolve(result)
            } catch (e: Exception) {
                promise.reject("PROBE_FAILED", e.message, e)
            } finally {
                conn?.disconnect()
            }
        }.start()
    }

    /** DNS config, Private-DNS (DoT) state, captive-portal capability, SSID. */
    @ReactMethod
    fun getNetworkStatus(promise: Promise) {
        Thread {
            try {
                val network = cm().activeNetwork
                val caps: NetworkCapabilities? = network?.let { cm().getNetworkCapabilities(it) }
                val lp: LinkProperties? = network?.let { cm().getLinkProperties(it) }

                val dnsServers = Arguments.createArray()
                lp?.dnsServers?.forEach { dnsServers.pushString(it.hostAddress) }

                val privateDnsActive = lp?.isPrivateDnsActive ?: false
                val privateDnsServer = lp?.privateDnsServerName

                val hasPortalCap = caps?.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL
                ) ?: false
                val validated = caps?.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_VALIDATED
                ) ?: false

                var gatewayIp: String? = null
                lp?.routes?.forEach { r ->
                    if (r.isDefaultRoute && r.hasGateway()) {
                        gatewayIp = r.gateway?.hostAddress
                    }
                }

                val localIp: String? = lp?.linkAddresses?.firstOrNull()?.address?.hostAddress

                // SSID needs location permission granted + location services on.
                // On API 31+ WifiManager.getConnectionInfo() is deprecated and
                // returns <unknown ssid>. Use TransportInfo from NetworkCapabilities.
                val ssid: String? = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && caps != null) {
                        val wifiInfo = caps.transportInfo as? WifiInfo
                        wifiInfo?.ssid?.replace("\"", "")?.takeIf { it != "<unknown ssid>" }
                    } else {
                        val wifi = reactContext.applicationContext
                            .getSystemService(Context.WIFI_SERVICE) as WifiManager
                        @Suppress("DEPRECATION")
                        wifi.connectionInfo?.ssid?.replace("\"", "")?.takeIf { it != "<unknown ssid>" }
                    }
                } catch (e: Exception) {
                    null
                }

                val map = Arguments.createMap().apply {
                    putArray("dnsServers", dnsServers)
                    putBoolean("privateDnsActive", privateDnsActive)
                    if (privateDnsServer != null) putString("privateDnsServer", privateDnsServer)
                    else putNull("privateDnsServer")
                    putBoolean("hasCaptivePortalCapability", hasPortalCap)
                    putBoolean("validated", validated)
                    if (ssid != null) putString("ssid", ssid) else putNull("ssid")
                    if (gatewayIp != null) putString("gatewayIp", gatewayIp) else putNull("gatewayIp")
                    if (localIp != null) putString("localIp", localIp) else putNull("localIp")
                }
                promise.resolve(map)
            } catch (e: Exception) {
                promise.reject("STATUS_FAILED", e.message, e)
            }
        }.start()
    }
}
