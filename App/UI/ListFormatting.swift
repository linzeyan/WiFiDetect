import Foundation

extension Array<String> {
    /// The list as Foundation words it, with a space where its Chinese meets a Latin
    /// name: zh-Hant joins "Safari和curl", while Traditional Chinese text, this app's
    /// strings included, sets Latin words and numbers apart ("Safari 和 curl").
    func formattedList(_ type: ListFormatStyle<StringStyle, [String]>.ListType, locale: Locale = .current) -> String {
        // Formatted with stand-ins, so the names themselves are never respaced.
        let marks = indices.map { Character(Unicode.Scalar(0xF0000 + UInt32($0))!) }
        var text = ""
        for character in marks.map(String.init).formatted(.list(type: type).locale(locale)) {
            let piece = marks.firstIndex(of: character).map { self[$0] } ?? String(character)
            if let last = text.last, let first = piece.first, Self.needsSpace(last, first) {
                text.append(" ")
            }
            text += piece
        }
        return text
    }

    /// Between Chinese and a Latin word or number, either way round.
    private static func needsSpace(_ a: Character, _ b: Character) -> Bool {
        isHan(a) && isLatin(b) || isLatin(a) && isHan(b)
    }

    private static func isHan(_ character: Character) -> Bool {
        character.unicodeScalars.contains { $0.properties.isIdeographic }
    }

    private static func isLatin(_ character: Character) -> Bool {
        character.isASCII && (character.isLetter || character.isNumber)
    }
}
