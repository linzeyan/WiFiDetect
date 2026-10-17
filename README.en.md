# WiFiDetect

[正體中文](README.md)

Wi-Fi signal, traffic monitoring and HTTP(S) debugging for macOS, with a companion app for iPhone and iPad.

## Features

### Mac

**Wi-Fi**
- Live signal (RSSI), noise, signal-to-noise ratio and transmit rate, charted over 1 minute to 7 days, with lines where calls and streaming start to suffer and where a Mac starts looking for a stronger access point. Grade thresholds are adjustable.
- The connection's channel, band and width, PHY mode, security and transmit power; its network name and BSSID once you allow location access.
- Nearby networks, and a channel map for 2.4, 5 and 6 GHz.
- A menu bar extra with the current signal and the last 5 minutes.
- Readings kept on the Mac for 7 days, and exported as CSV.

**Traffic**
- Bytes and packets per second, in and out, on the interface you choose.
- Every connection: protocol, addresses, domain (from TLS and QUIC SNI, DNS, or a reverse lookup), service, country and network owner, the app behind it, traffic and TCP round-trip time.
- Top hosts, services, apps and countries.
- BPF filters, recording to PCAP, and opening pcap and pcapng files.
- Favorites, an IP blacklist, and notifications for traffic above a limit, blacklisted addresses and favorite hosts.
- Router Flows: NetFlow v9 and IPFIX from your router, for the devices the Mac can't see.
- Optional: a content filter network extension that names the app behind every connection, including the ones the socket table misses.

**HTTP(S) debugging**
- A proxy on 127.0.0.1 that the system proxy points at while it runs. The proxy settings are put back when it stops, even if the app crashes.
- HTTPS decrypted for the hosts you list, with a certificate authority made on your Mac; everything else passes through unread.
- HTTP/1.1, HTTP/2 (gRPC included) and WebSocket messages.
- Map Local, Map Remote, Breakpoints, JavaScript scripts, throttling with Chrome DevTools' presets, and HAR export.
- Optional: a transparent proxy network extension for apps that ignore the system proxy.

### iPhone and iPad

- **Mac**: a Mac's live Wi-Fi signal, noise, SNR and charts, over your local network.
- **This Device**: the system's rating of this Wi-Fi link (iOS 26 and later), and round trips to your router and the internet, timed once a second: median, jitter and loss.

iOS gives apps no Wi-Fi signal strength, so signal readings come from a Mac.

## Requirements

- Mac: macOS 26 or later.
- iPhone and iPad: iOS and iPadOS 18 or later. Link quality needs 26.
- Languages: Traditional Chinese and English, following the system's language; any other language gets English.

## Install

- **Mac**: download `WiFiDetect.zip` from the [latest release](https://github.com/linzeyan/WiFiDetect/releases/latest), unzip it, move WiFiDetect to Applications and open it. It's signed with Developer ID and notarized by Apple.
- **iPhone and iPad**: on the App Store, coming soon.

## Use

### Wi-Fi

Wi-Fi › Signal starts measuring when WiFiDetect opens. Choose a time window above the charts; Show Network Names asks for the location access macOS requires for them. Export CSV… in the toolbar saves the readings in the window. Wi-Fi › Nearby Networks scans for networks around you.

### Traffic

Reading packets needs a helper that runs as root, installed once:

1. Settings › Helper › Install.
2. Allow WiFiDetect in System Settings › General › Login Items & Extensions (Open Login Items takes you there).
3. Traffic › Overview › Start Capture.

Traffic › Connections lists every connection. Record PCAP… saves packets to a file, and File › Open Capture… (⌘O) shows a saved one.

- To name the app behind every connection, turn on Settings › Traffic › Name apps with a content filter, and allow the extension and the content filter when macOS asks.
- To see the rest of your network, turn on Settings › Traffic › Collect flows from routers, and point your router's NetFlow v9 or IPFIX export at this Mac, port 4739. The flows show in Traffic › Router Flows.

### HTTP(S) debugging

1. Install the helper as above: it's what switches the system proxy.
2. HTTP › Requests › Start Proxy. Requests from apps that use the system proxy show up.
3. To read HTTPS, click Settings › Proxy › Create and Trust… (macOS asks for your password), then list the hosts under Decrypt HTTPS for, such as `api.example.com` or `*.example.com`.
4. Settings › Rules holds Map Local, Map Remote, Breakpoints and Scripts.

Stop Proxy puts the system proxy back. When you're done debugging, Settings › Proxy › Remove… deletes the certificate authority.

For apps that ignore the system proxy, turn on Settings › Proxy › Capture apps that ignore the system proxy and add them to its list.

### iPhone and iPad

1. On the Mac, turn on Settings › Wi-Fi › Share readings with iPhone and iPad.
2. Open WiFiDetect on an iPhone or iPad on the same network. The Mac page finds the Mac.

Anyone on the network can read what the Mac shares: signal, noise, channel and transmit rate, never the network's name.

## Privacy

WiFiDetect collects nothing: no accounts, analytics or ads, and everything stays on your devices and your network. See [PRIVACY.md](PRIVACY.md).

## Build from source

Built with Xcode 27.1 and [XcodeGen](https://github.com/yonaskolb/XcodeGen). The Xcode project is generated from `project.yml` and isn't committed.

```sh
make build     # the app and its helper
make run       # build and open it
make test      # unit tests
make ios       # the iPhone and iPad app, for the simulator
make strings   # new interface strings into the catalogs; fails on untranslated ones
make dist      # Developer ID build with the network extensions, notarized: build/dist/WiFiDetect.zip
make release   # make dist, then a GitHub release of it
make help      # everything else
```

The first build fetches the DB-IP Lite databases into `App/GeoIP`. Signing uses team `NKJSLB6HBR`: to build under your own team, change it in `project.yml`, `Shared/HelperProtocol.swift` (the helper only talks to apps from its team) and `scripts/dist.sh`, and `bundleIdPrefix` in `project.yml`.

The interface strings are written in English and translated into Traditional Chinese in each target's `Localizable.xcstrings` and `InfoPlist.xcstrings`. Command-line builds don't update the catalogs: after adding interface strings, `make strings` merges them in and lists the ones still to translate.

### Releasing the Mac app

Each release is built and notarized on a Mac, then published here:

1. Raise `MARKETING_VERSION` in `project.yml`, commit, and push `main`.
2. `make release`. It checks that the working tree is clean, that GitHub's `main` is the commit being built, and that the version isn't released yet; then runs `make dist` and creates release `v<version>` with `WiFiDetect.zip`. `NOTES="…" make release` sets the release notes.

It needs `gh` signed in, the Developer ID certificate in the keychain and the notarytool keychain profile `zeyanlin-notary` (another with `NOTARY_PROFILE=`).

## Acknowledgements

- [IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0.
- [SwiftNIO](https://github.com/apple/swift-nio), [swift-nio-ssl](https://github.com/apple/swift-nio-ssl), [swift-nio-http2](https://github.com/apple/swift-nio-http2) and [swift-certificates](https://github.com/apple/swift-certificates), Apache 2.0.

[NOTICE.md](NOTICE.md) lists every third-party package with its notices; the Mac app carries a copy.

## License

[Apache License 2.0](LICENSE).
