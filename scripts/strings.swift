// `make strings`: merges the strings the last `make build` and `make ios` found into each
// app's Localizable.xcstrings, then fails on anything left untranslated. Xcode updates
// the catalogs as it builds; xcodebuild doesn't.
import Foundation

let intermediates = "build/Build/Intermediates.noindex/WiFiDetect.build"
let apps = [
    (catalog: "App/Localizable.xcstrings", stringsdata: "\(intermediates)/Debug/WiFiDetect.build"),
    (catalog: "iOS/Localizable.xcstrings", stringsdata: "\(intermediates)/Debug-iphonesimulator/WiFiDetectCompanion.build"),
]
// Info.plist as xcodegen writes it, and where its usage descriptions are translated.
let infoPlists = [
    (plist: "App/Info.plist", catalog: "App/InfoPlist.xcstrings"),
    (plist: "Extension/Info.plist", catalog: "Extension/InfoPlist.xcstrings"),
    (plist: "iOS/Info.plist", catalog: "iOS/InfoPlist.xcstrings"),
]
let language = "zh-Hant"
var problems: [String] = []

func strings(_ catalog: String) throws -> [String: [String: Any]] {
    let json = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(filePath: catalog))) as? [String: Any]
    return json?["strings"] as? [String: [String: Any]] ?? [:]
}

/// A plain translation, or plural variations, all marked translated.
func isTranslated(_ localization: Any?) -> Bool {
    guard let localization = localization as? [String: Any] else { return false }
    if let unit = localization["stringUnit"] as? [String: Any] {
        return unit["state"] as? String == "translated"
    }
    return localization["variations"] != nil
}

for app in apps {
    let files = (FileManager.default.enumerator(atPath: app.stringsdata)?.allObjects as? [String] ?? [])
        .filter { $0.hasSuffix(".stringsdata") }
        .map { "\(app.stringsdata)/\($0)" }
    guard !files.isEmpty else {
        problems.append("\(app.stringsdata) has no .stringsdata: run make build and make ios first")
        continue
    }
    let sync = Process()
    sync.executableURL = URL(filePath: "/usr/bin/xcrun")
    sync.arguments = ["xcstringstool", "sync", app.catalog] + files.flatMap { ["--stringsdata", $0] }
    try sync.run()
    sync.waitUntilExit()
    guard sync.terminationStatus == 0 else {
        problems.append("\(app.catalog): xcstringstool sync failed")
        continue
    }
    let entries = try strings(app.catalog)
    for (key, entry) in entries.sorted(by: { $0.key < $1.key }) where entry["shouldTranslate"] as? Bool != false {
        let localizations = entry["localizations"] as? [String: Any]
        if !isTranslated(localizations?[language]) {
            problems.append("\(app.catalog): no \(language) for \"\(key)\"")
        }
    }
    // Xcode makes en.lproj only when English has a string of its own, and the App Store
    // lists only the languages with an .lproj (QA1828).
    if !entries.values.contains(where: { ($0["localizations"] as? [String: Any])?["en"] != nil }) {
        problems.append("\(app.catalog): no English string of its own, so the app would ship without en.lproj")
    }
}

for target in infoPlists {
    guard let plist = NSDictionary(contentsOfFile: target.plist) as? [String: Any] else {
        problems.append("\(target.plist) is missing: run make generate first")
        continue
    }
    let entries = try strings(target.catalog)
    for key in plist.keys.sorted() where key.hasSuffix("UsageDescription") {
        if !isTranslated((entries[key]?["localizations"] as? [String: Any])?[language]) {
            problems.append("\(target.catalog): no \(language) for \(key)")
        }
    }
}

if problems.isEmpty {
    print("strings: every string has a \(language) translation")
} else {
    problems.forEach { print("strings: \($0)") }
    exit(1)
}
