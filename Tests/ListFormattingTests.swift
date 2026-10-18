import Foundation
import Testing
@testable import WiFiDetect

struct ListFormattingTests {
    private let zh = Locale(identifier: "zh-Hant-TW")

    /// zh-Hant's conjunction runs into Latin names ("Safari和curl"); the app's own
    /// strings set Latin words and numbers apart, so the lists in them must too.
    @Test func chineseSetsLatinNamesApart() {
        #expect(["Safari", "curl"].formattedList(.and, locale: zh) == "Safari 和 curl")
        #expect(["Safari", "Chrome", "curl"].formattedList(.and, locale: zh) == "Safari、Chrome 和 curl")
        #expect(["192.168.1.5", "10.0.0.2"].formattedList(.or, locale: zh) == "192.168.1.5 或 10.0.0.2")
    }

    /// Spacing goes only where a name meets the list's own words: Chinese names stay
    /// joined, and a name is shown as written, mixed or not.
    @Test func namesAreLeftAsWritten() {
        #expect(["備忘錄", "計算機"].formattedList(.and, locale: zh) == "備忘錄和計算機")
        #expect(["QQ音樂", "curl"].formattedList(.and, locale: zh) == "QQ音樂和 curl")
        #expect(["Safari"].formattedList(.and, locale: zh) == "Safari")
    }

    @Test func englishIsFoundations() {
        let en = Locale(identifier: "en")
        #expect(["Safari", "Chrome", "curl"].formattedList(.and, locale: en) == ["Safari", "Chrome", "curl"].formatted(.list(type: .and).locale(en)))
    }
}
