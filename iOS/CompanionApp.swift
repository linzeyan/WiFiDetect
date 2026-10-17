import SwiftUI

@main
struct CompanionApp: App {
    @State private var mac = MacClient()
    @State private var phone = PhoneMonitor()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(mac)
                .environment(phone)
        }
    }
}

private struct RootView: View {
    private enum Page: String {
        case mac, phone
    }

    @Environment(MacClient.self) private var mac
    // Reopens on the page last used. Also settable at launch (`-page phone`).
    @AppStorage("page") private var page = Page.mac
    // Once the user has said yes to looking for Macs, later launches look right away.
    @AppStorage("searchesForMacs") private var searchesForMacs = false

    var body: some View {
        TabView(selection: $page) {
            Tab("Mac", systemImage: "laptopcomputer", value: .mac) { MacView() }
            Tab("This Device", systemImage: PhoneView.symbol, value: .phone) { PhoneView() }
        }
        .task(id: searchesForMacs) {
            if searchesForMacs { mac.start() }
        }
    }
}
