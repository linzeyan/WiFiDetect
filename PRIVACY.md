# WiFiDetect Privacy Policy

Last updated: October 17, 2026

WiFiDetect is made by Zeyan Lin. This policy covers WiFiDetect for iPhone and iPad and WiFiDetect for Mac.

**In short: WiFiDetect collects nothing.** It has no accounts, analytics, advertising or tracking, and contains no third-party code that does. Nothing it measures or shows is sent to the developer or anyone else. Everything stays on your devices and your own network.

## WiFiDetect for iPhone and iPad

- **Wi-Fi network name.** iOS shows the name of the Wi-Fi network only to apps with location access, so WiFiDetect asks for it, and only when you tap Show Name. It reads the network's name and nothing else: it never asks where you are, and the name isn't stored.
- **Your Mac's readings.** To show a Mac's Wi-Fi chart, the app looks for Macs running WiFiDetect on your local network (Bonjour) and connects to the one you choose. It receives that Mac's signal, noise, channel and transmit rate, which it keeps in memory while it runs and never stores.
- **Round trips.** While the This Device page is open, the app times round trips (ICMP echo, "ping") to your router and to 1.1.1.1, a public address run by Cloudflare. These packets carry nothing about you or your device. Like any internet traffic, they reach Cloudflare from your network's public IP address. The results are kept in memory for one minute and never stored.
- **Settings.** The page you last had open and whether to look for Macs are saved on the device, in the app's own preferences.

## WiFiDetect for Mac

- **Wi-Fi readings.** Signal, noise and the time of each reading from the last 7 days are kept on the Mac, in ~/Library/Application Support/WiFiDetect/Wi-Fi Readings, never with the network's name. Settings › Wi-Fi deletes them.
- **Traffic monitoring.** A helper that runs as root reads packets on the Mac to list its connections. Connections are kept in memory, are not stored, and go into a capture file only when you save one. Countries and network owners are looked up in a database that comes with the app (DB-IP Lite), not online.
- **HTTP(S) debugging.** The proxy listens only on the Mac itself (127.0.0.1). To read HTTPS, WiFiDetect creates a certificate authority on the Mac; its private key stays in your keychain. HTTPS is decrypted only for the hosts you list. Requests are kept in memory and are not stored, and go into a file only when you export them. Map Local, Map Remote, Breakpoint and Script rules run on the Mac.
- **App attribution (optional network extension).** Names the app behind each connection. What it sees stays on the Mac.
- **Sharing with iPhone and iPad (off by default).** When you turn it on, the Mac offers its signal, noise, channel and transmit rate on your local network. Anyone on that network can then see them, but never the network's name.
- **Router Flows (off by default).** When you turn it on, the Mac receives flow records your router sends to it on your local network. They are kept in memory and not stored.
- **Settings** and the rules you create are saved in the app's preferences on the Mac.

## Crash reports

If you've chosen in your device's settings to share analytics with app developers, Apple may send the developer crash reports for WiFiDetect. Apple handles these under its own privacy policy; they contain no data WiFiDetect collected.

## Children

WiFiDetect collects no information from anyone, including children.

## Changes

If this policy changes, the new version will be posted here with a new date.

## Contact

Questions about this policy or WiFiDetect: zeyanlin@outlook.com, or open an issue at https://github.com/linzeyan/WiFiDetect/issues.

---

# WiFiDetect 隱私權政策

最後更新：2026 年 10 月 17 日

WiFiDetect 由 Zeyan Lin 開發。本政策適用於 iPhone 與 iPad 版的 WiFiDetect，以及 Mac 版的 WiFiDetect。

**簡單來說：WiFiDetect 不蒐集任何資料。** 沒有帳號、分析、廣告或追蹤，也不含會做這些事的第三方程式碼。它量到的、顯示的一切都不會傳給開發者或任何人，全部留在你的裝置與你自己的網路裡。

## iPhone 與 iPad 版

- **Wi-Fi 網路名稱**：iOS 只讓有位置權限的 app 看到 Wi-Fi 網路名稱，所以 WiFiDetect 只在你點「Show Name」時才要求位置權限。它只讀網路名稱，從不讀取你的位置，名稱也不會被儲存。
- **Mac 的讀數**：為了顯示 Mac 的 Wi-Fi 圖表，app 會在區域網路上尋找執行 WiFiDetect 的 Mac（Bonjour），並連到你選的那一台，接收它的訊號、雜訊、頻道與傳輸速率。這些資料只在 app 執行時存在記憶體裡，不會儲存。
- **往返時間**：開著「This Device」頁面時，app 會量測到你的路由器與 1.1.1.1（Cloudflare 營運的公開位址）的往返時間（ICMP echo，即 ping）。這些封包不帶任何關於你或你裝置的資訊；如同所有網際網路流量，它們會從你網路的公開 IP 位址抵達 Cloudflare。結果在記憶體中保留一分鐘，不會儲存。
- **設定**：上次開啟的頁面、是否尋找 Mac，存在裝置上 app 自己的偏好設定裡。

## Mac 版

- **Wi-Fi 讀數**：最近 7 天每筆讀數的訊號、雜訊與時間存在 Mac 上的 ~/Library/Application Support/WiFiDetect/Wi-Fi Readings，從不包含網路名稱。可在 Settings › Wi-Fi 刪除。
- **流量監看**：一個以 root 執行的 helper 在 Mac 上讀取封包，列出連線。連線只存在記憶體裡、不會儲存，只有你存成擷取檔時才寫入檔案。國家與網路業者用 app 內附的資料庫（DB-IP Lite）查詢，不上網查。
- **HTTP(S) 除錯**：proxy 只在 Mac 本機（127.0.0.1）監聽。為了讀取 HTTPS，WiFiDetect 會在 Mac 上建立一個憑證授權單位，私鑰留在你的鑰匙圈裡。只有你列出的主機才會被解密。請求只存在記憶體裡、不會儲存，只有你匯出時才寫入檔案。Map Local、Map Remote、Breakpoint、Script 規則都在 Mac 上執行。
- **App 歸屬（選用的網路延伸功能）**：標出每條連線背後的 app，看到的內容留在 Mac 上。
- **分享給 iPhone 與 iPad（預設關閉）**：開啟後，Mac 會在區域網路上提供它的訊號、雜訊、頻道與傳輸速率，同一網路上的任何人都看得到，但從不包含網路名稱。
- **Router Flows（預設關閉）**：開啟後，Mac 接收路由器在區域網路上傳給它的 flow 紀錄，只存在記憶體裡，不會儲存。
- **設定**與你建立的規則存在 Mac 上 app 的偏好設定裡。

## 當機報告

如果你在裝置設定中選擇與 app 開發者分享分析資料，Apple 可能會把 WiFiDetect 的當機報告傳給開發者。這由 Apple 依其隱私權政策處理，其中不含 WiFiDetect 蒐集的資料。

## 兒童

WiFiDetect 不蒐集任何人的資訊，包括兒童。

## 變更

本政策若有變更，新版本會公布在此處並更新日期。

## 聯絡方式

對本政策或 WiFiDetect 有任何問題：zeyanlin@outlook.com，或在 https://github.com/linzeyan/WiFiDetect/issues 開 issue。
