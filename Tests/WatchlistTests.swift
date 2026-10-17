import Foundation
import Testing
@testable import WiFiDetect

private func ip(_ text: String) -> IPAddress { IPAddress(text)! }

// MARK: Blacklist

struct IPRangeTests {
    /// A range covers its first and last address and stops there: one off in the mask
    /// and the neighbor network's hosts are flagged too, or the range's own edges missed.
    @Test func v4PrefixBoundaries() {
        let range = IPRange("203.0.113.0/24")!
        #expect(range.contains(ip("203.0.113.0")))
        #expect(range.contains(ip("203.0.113.255")))
        #expect(!range.contains(ip("203.0.112.255")))
        #expect(!range.contains(ip("203.0.114.0")))
        // Not on an octet, and written with host bits set, as people paste them.
        let wide = IPRange("203.0.113.9/22")!
        #expect(wide.contains(ip("203.0.112.0")))
        #expect(wide.contains(ip("203.0.115.255")))
        #expect(!wide.contains(ip("203.0.111.255")))
        #expect(!wide.contains(ip("203.0.116.0")))
    }

    /// A bare address is that address alone; /0 is every address of its family and
    /// still none of the other.
    @Test func v4SingleAddressAndEverything() {
        let one = IPRange("198.51.100.7")!
        #expect(one.prefix == 32)
        #expect(one.contains(ip("198.51.100.7")))
        #expect(!one.contains(ip("198.51.100.6")))
        #expect(!IPRange("198.51.100.7/32")!.contains(ip("198.51.100.8")))
        let all = IPRange("0.0.0.0/0")!
        #expect(all.contains(ip("0.0.0.0")))
        #expect(all.contains(ip("255.255.255.255")))
        #expect(!all.contains(ip("::1")))
    }

    /// IPv6 is held as two 64-bit halves, so a prefix in the high half, one at the seam
    /// and one in the low half each take a different path through the masks.
    @Test func v6Prefixes() {
        let documentation = IPRange("2001:db8::/32")!
        #expect(documentation.contains(ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")))
        #expect(!documentation.contains(ip("2001:db9::")))
        let seam = IPRange("2001:db8:0:1::/64")!
        #expect(seam.contains(ip("2001:db8:0:1:ffff:ffff:ffff:ffff")))
        #expect(!seam.contains(ip("2001:db8:0:2::")))
        let low = IPRange("2001:db8::ff00/120")!
        #expect(low.contains(ip("2001:db8::ffff")))
        #expect(!low.contains(ip("2001:db8::1:ff00")))
        let one = IPRange("2001:db8::1")!
        #expect(one.prefix == 128)
        #expect(one.contains(ip("2001:db8::1")))
        #expect(!one.contains(ip("2001:db8::2")))
        // The same low half under another high half is another host.
        #expect(!one.contains(ip("2001:db9::1")))
        let all = IPRange("::/0")!
        #expect(all.contains(ip("ffff::1")))
        #expect(!all.contains(ip("10.0.0.1")))
    }

    /// Anything that isn't plainly an address or a range is refused, not guessed at: a
    /// guess could flag, or quietly fail to flag, a whole network.
    @Test(arguments: ["", "example.com", "10.0.0.256", "1.2.3", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/", "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/8/8", "10.0.0.0 /8"])
    func refusesInvalidText(text: String) {
        #expect(IPRange(text) == nil)
    }
}

struct BlacklistTests {
    /// Lists arrive pasted or from files written elsewhere: comments, blank lines,
    /// Windows line ends and stray spaces all read, and each bad line comes back with its
    /// number, so Settings can say which one instead of dropping it unseen.
    @Test func readsListsAndReportsBadLines() {
        let text = "# my list\r\n203.0.113.0/24 ; SBL123\r\n\r\n  2001:db8::/32  \nnot-an-ip\n10.0.0.0/33 # typo\n198.51.100.7"
        let list = Blacklist(text)
        #expect(list.entries.map(\.description) == ["203.0.113.0/24", "2001:db8::/32", "198.51.100.7"])
        #expect(list.invalid.map(\.line) == [5, 6])
        #expect(list.invalid.map(\.text) == ["not-an-ip", "10.0.0.0/33"])
    }

    /// The entry an address falls in is what the table's tooltip and the notification
    /// name, so it has to be the one that matched.
    @Test func findsTheMatchingEntry() {
        let list = Blacklist("198.51.100.7\n203.0.113.0/24")
        #expect(list.entry(containing: ip("203.0.113.80"))?.description == "203.0.113.0/24")
        #expect(list.entry(containing: ip("198.51.100.7"))?.description == "198.51.100.7")
        #expect(list.entry(containing: ip("198.51.100.8")) == nil)
    }
}

// MARK: Favorites

struct FavoritesTests {
    private let address = ip("93.184.216.34")

    /// Starred by domain: every connection to that name counts, whichever address the CDN
    /// gives out, and DNS's case doesn't matter. Another name at the same address isn't it.
    @Test func matchesByDomain() {
        var favorites = Favorites()
        favorites.set(true, domain: "Example.com", address: address)
        #expect(favorites.hosts == ["example.com"])
        #expect(favorites.match(domain: "example.com", address: ip("203.0.113.1")) == "example.com")
        #expect(favorites.match(domain: "EXAMPLE.COM", address: address) == "example.com")
        #expect(favorites.match(domain: "www.example.com", address: address) == nil)
        #expect(favorites.match(domain: nil, address: address) == nil)
    }

    /// Starred by address before a name was known: it's still the same host once its
    /// domain turns up, starring it again doesn't add the name as a second favorite, and
    /// unstarring takes the star off whichever name had it.
    @Test func matchesByAddress() {
        var favorites = Favorites()
        favorites.set(true, domain: nil, address: address)
        #expect(favorites.match(domain: "example.com", address: address) == "93.184.216.34")
        #expect(favorites.match(domain: nil, address: ip("93.184.216.35")) == nil)
        favorites.set(true, domain: "example.com", address: address)
        #expect(favorites.hosts == ["93.184.216.34"])
        favorites.set(false, domain: "example.com", address: address)
        #expect(favorites.hosts.isEmpty)
    }
}

// MARK: Notifications

struct ThresholdAlarmTests {
    private func download(_ rates: [Int], from start: Int = 100) -> [Int: TrafficCounts] {
        Dictionary(uniqueKeysWithValues: rates.enumerated().map { (start + $0.offset, TrafficCounts(bytesIn: $0.element)) })
    }

    private func makeAlarm(_ direction: TrafficDirection = .download) -> ThresholdAlarm {
        var alarm = ThresholdAlarm()
        alarm.limit = 1_000
        alarm.direction = direction
        return alarm
    }

    /// One notification as the fifth second over the limit comes in, none for every
    /// second the download goes on after it, and another only once it eased off and
    /// came back.
    @Test func firesOncePerSustainedRun() {
        var alarm = makeAlarm()
        let seconds = download([2_000, 2_000, 2_000, 2_000, 2_000, 2_000, 500, 2_000, 2_000, 2_000, 2_000, 2_000])
        let fired = (100 ..< 112).filter { alarm.update(seconds, end: $0) }
        #expect(fired == [104, 111])
    }

    /// Four seconds, a second with nothing captured, or a second exactly at the limit
    /// isn't traffic staying above it.
    @Test func shortOrBrokenRunsDontFire() {
        var alarm = makeAlarm()
        var gap = download([2_000, 2_000, 2_000, 2_000, 2_000])
        gap[102] = nil
        let fired = [
            alarm.update(download([2_000, 2_000, 2_000, 2_000]), end: 103),
            alarm.update(gap, end: 104),
            alarm.update(download([2_000, 2_000, 1_000, 2_000, 2_000]), end: 104),
            alarm.update(download([2_000, 2_000, 1_001, 2_000, 2_000]), end: 104),
        ]
        #expect(fired == [false, false, false, true])
    }

    /// The setting picks the side measured: 600 bytes each way is under a 1,000 limit
    /// either way and over it together.
    @Test(arguments: [(TrafficDirection.download, false), (.upload, false), (.total, true)])
    func measuresTheChosenDirection(direction: TrafficDirection, fires: Bool) {
        var alarm = makeAlarm(direction)
        let seconds = Dictionary(uniqueKeysWithValues: (100 ..< 105).map { ($0, TrafficCounts(bytesIn: 600, bytesOut: 600)) })
        let fired = alarm.update(seconds, end: 104)
        #expect(fired == fires)
    }
}

struct RateLimiterTests {
    /// A storm of connections to one blacklist entry is one notification a minute, while
    /// another entry still gets its own.
    @Test func oncePerSubjectPerMinute() {
        var limiter = RateLimiter()
        let start = Date(timeIntervalSince1970: 1000)
        let allowed = [
            limiter.allow("blacklist 203.0.113.0/24", at: start),
            limiter.allow("blacklist 203.0.113.0/24", at: start.addingTimeInterval(1)),
            limiter.allow("blacklist 198.51.100.7", at: start.addingTimeInterval(2)),
            limiter.allow("blacklist 203.0.113.0/24", at: start.addingTimeInterval(59)),
            limiter.allow("blacklist 203.0.113.0/24", at: start.addingTimeInterval(60)),
        ]
        #expect(allowed == [true, false, true, false, true])
    }
}

struct NewFlowsTests {
    private func flow(_ port: UInt16, firstSeen: Double) -> Flow {
        let key = FlowKey(proto: 6, local: ip("192.168.1.10"), localPort: port, remote: ip("93.184.216.34"), remotePort: 443)
        let date = Date(timeIntervalSince1970: firstSeen)
        return Flow(key: key, firstSeen: date, lastSeen: date)
    }

    private func at(_ seconds: Double) -> Date { Date(timeIntervalSince1970: seconds) }

    /// One notification per connection: handed out on the first check after it has had
    /// time to get its name, then never again however long it stays in the table.
    @Test func handsOutEachConnectionOnce() {
        var tracker = NewFlows()
        let first = flow(52000, firstSeen: 100)
        let second = flow(52001, firstSeen: 102)
        let handedOut = [
            tracker.take([first], now: at(101)),
            tracker.take([first], now: at(102)),
            tracker.take([first, second], now: at(103)),
            tracker.take([first, second], now: at(104)),
            tracker.take([first, second], now: at(105)),
        ].map { $0.map(\.key) }
        #expect(handedOut == [[], [first.key], [], [second.key], []])
    }

    /// The table drops a connection after 10 idle minutes, and one that comes back on
    /// the same ports is a new row there; it's a new connection here too.
    @Test func returningConnectionIsNewAgain() {
        var tracker = NewFlows()
        let first = flow(52000, firstSeen: 100)
        _ = tracker.take([first], now: at(103))
        _ = tracker.take([], now: at(800))
        let handedOut = tracker.take([flow(52000, firstSeen: 900)], now: at(903))
        #expect(handedOut.map(\.key) == [first.key])
    }
}
