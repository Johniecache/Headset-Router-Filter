# Headset WiFi Filter

A travel router and DNS security gateway built on an ESP32, housed in the salvaged shell of a broken SteelSeries Arctis Nova 7 headset. It creates its own private WiFi network, routes your devices out through an untrusted hotspot (hotel, airport, cafe, phone tethering), filters ads and trackers at the DNS layer, and encrypts all DNS lookups over HTTPS so the network you are borrowing cannot see or tamper with them.

This is a personal learning and portfolio project, not audited security software. See the Security model section below for an honest account of what it does and does not protect.

## What it does

* **Private NAT router.** Brings up its own access point ("HeadsetFilter") and routes connected clients out through whatever upstream WiFi you join, using NAT (NAPT) so several devices can share one hotspot login.
* **DNS filtering.** Sinkholes ad and tracker domains from a configurable blocklist before any query leaves the device.
* **DNS over HTTPS (DoH).** Forwards allowed lookups to Cloudflare over TLS on port 443 instead of plaintext port 53. This keeps DNS private on hostile networks and works on hotspots that block or hijack port 53. Certificates are validated against a trusted CA bundle, and the device falls back to plain UDP automatically if DoH is ever unreachable, so it cannot strand you offline.
* **Live web dashboard.** A password protected status page at `http://192.168.4.1/` shows uplink status, connected clients, DNS allowed/blocked counts, recent queries, and DoH health. Settings (networks, blocklist, passwords) are editable from the browser and persist across reboots.
* **Captive portal detection.** Probes for the typical "click to continue" hotel/airport login walls and reports when one is in the way.
* **MAC cloning.** Optionally clones an authorized device's MAC address onto the uplink, which helps when a captive portal has already approved that device.
* **Security monitors (experimental).** Optional promiscuous mode detection of deauthentication floods and evil twin access points. Disabled by default. See limitations.

## Hardware

| Part | Role |
|------|------|
| ESP32-WROOM-DA module | Main controller and dual radios (2.4 GHz only) |
| Salvaged Arctis Nova 7 Gen 1 shell | Enclosure (e-waste given a second life) |
| Li-Po pouch cell | Battery |
| TP4056 module | Li-Po charging and protection |
| MT3608 boost converter | Battery voltage up to 5 V for the ESP32 |

Power path: Li-Po &rarr; TP4056 &rarr; MT3608 boost (~5.0v) &rarr; ESP32 Vcc.

## How it works

The ESP32 runs as access point and station at the same time on its single 2.4 GHz radio. The station side joins your chosen upstream network and the access point side serves your devices. NAPT on the access point interface translates client traffic out through the station interface. A small UDP listener on port 53 intercepts every client DNS query, checks it against the blocklist, and either sinkholes it or forwards it (over DoH when available, plain UDP otherwise). The dashboard is served by the on device HTTP server with HTTP basic authentication on every endpoint.

## Limitations

These are real constraints of the platform, documented on purpose.

* **2.4 GHz only.** The ESP32 cannot see or join 5 GHz networks. Many modern hotspots are 5 GHz, so check before relying on it. True dual band would require different hardware (like a Raspberry Pi).
* **Throughput.** A single radio acting as both access point and station roughly halves usable bandwidth. This is fine for browsing, messaging, and light streaming, but it is not a high throughput router.
* **Security monitors share the radio.** The deauth and evil twin monitors use promiscuous mode on the same radio that is serving clients. They can be unstable under load and only observe the current channel, so an attack on another channel is invisible. They are off by default (`ENABLE_MONITORS 0`). Treat them as a demo, not a guarantee. Genuine passive monitoring wants a second, dedicated radio.
* **DoH adds latency on the first lookup.** The first query after boot pays a TLS handshake. After that the connection is reused and subsequent lookups are faster.

## Security model

What this device gives you:

* An isolated, password protected network of your own on top of a shared hotspot.
* DNS lookups that are filtered for ads and trackers and encrypted to the resolver, so the local network cannot snoop or hijack your DNS.
* A clear view, on the dashboard, of what is being resolved and blocked.

What it does NOT give you:

* It is not a VPN. Apart from DNS, your traffic is encrypted only as far as the apps and sites themselves encrypt it (which today is most things over HTTPS, but not all). For full traffic encryption on a hostile network, run a real VPN on top.
* It is not audited and makes no cryptographic guarantees beyond standard TLS certificate validation for DoH.
* The security monitors are best effort and single channel, as noted above.

## Build and flash

Built with PlatformIO using the ESP-IDF framework.

1. Install [PlatformIO](https://platformio.org/) (the VS Code extension is easiest).
2. Set up your credentials:
   ```
   cp src/secrets.example.h src/secrets.h
   ```
   then edit `src/secrets.h` with your real values. This file is gitignored and is never committed.
3. Build and upload:
   ```
   pio run --target upload
   ```
4. Watch the serial log:
   ```
   pio device monitor
   ```

The first build is slower and the firmware is larger than a bare sketch because it includes the TLS stack and CA bundle. The partition table (`partitions.csv`) is sized for the 2 MB flash on this module.

## Configuration

* Join the `HeadsetFilter` network with the access point password from your `secrets.h`.
* Open `http://192.168.4.1/` and log in with the dashboard credentials from your `secrets.h`.
* Change the upstream network, blocklist, dashboard password, and MAC clone from the settings page. Changes are saved to flash and survive reboots.

**Change the default passwords before real use.** Shipping a security device on `changeme123` defeats the purpose. Set strong values in `secrets.h` (for the build defaults) and on the settings page (for the live device).

## Repository layout

```
.
|-- src/
|   |-- pocket_wifi_filter.c     standard firmware (ESP-IDF, the canonical build)
|   |-- secrets.example.h        credential template (committed)
|   |-- secrets.h                your real credentials (gitignored, you create this)
|   `-- CMakeLists.txt
|-- legacy/
|   `-- arduino/                 original Arduino sketch, kept for reference
|                                (predates NAT routing)
|-- docs/                        wiring guide and teardown notes
|-- platformio.ini
|-- partitions.csv               2 MB flash layout
|-- sdkconfig.defaults
|-- LICENSE
`-- README.md
```

## Roadmap

Possible future additions, in rough order of value:

* Bind the dashboard to the access point interface only, so it is not reachable from the hostile uplink side (currently it listens on all interfaces and is gated by the admin password).
* Over the air firmware updates, so the device can be reflashed without opening the headset.
* A configurable choice of DoH provider.
* Per client statistics on the dashboard.

## License

Released under the MIT License. See [LICENSE](LICENSE).
