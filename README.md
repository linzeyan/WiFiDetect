# WiFiDetect

[English](README.en.md)

macOS 上的 Wi-Fi 訊號、流量監控與 HTTP(S) 除錯工具，另有 iPhone 與 iPad 的配套 App。

## 功能

### Mac

**Wi-Fi**
- 即時訊號（RSSI）、雜訊、訊雜比與傳輸速率，圖表可看 1 分鐘到 7 天，並標出通話與串流開始變差、以及 Mac 開始尋找訊號更強的無線基地台的位置。訊號等級的門檻可以調整。
- 目前連線的頻道、頻段與頻寬、PHY 模式、安全性與傳輸功率；允許定位權限後，也會顯示網路名稱與 BSSID。
- 附近的網路，以及 2.4、5、6 GHz 的頻道圖。
- 選單列項目，顯示目前的訊號與最近 5 分鐘的圖表。
- 讀數在 Mac 上保存 7 天，可輸出成 CSV。

**流量**
- 所選網路介面每秒傳入、傳出的位元組與封包數。
- 每一條連線：協定、位址、網域（來自 TLS 與 QUIC 的 SNI、DNS 或反向查詢）、服務、國家或地區與網路擁有者、背後的 App、流量與 TCP 往返時間。
- 流量最多的主機、服務、App 與國家或地區。
- BPF 過濾器、錄製成 PCAP，以及打開 pcap 與 pcapng 檔案。
- 最愛、IP 黑名單，以及流量超過上限、黑名單位址與最愛主機有新連線時的通知。
- 路由器流量：接收路由器送出的 NetFlow v9 與 IPFIX，看見 Mac 看不到的裝置。
- 選用：內容過濾器網路延伸功能，標出每一條連線背後的 App，包括 socket 表漏掉的連線。

**HTTP(S) 除錯**
- 在 127.0.0.1 上執行的代理伺服器，執行期間系統代理伺服器會指向它。停止時會還原代理伺服器設定，即使 App 當掉也一樣。
- 只解密你列出的主機的 HTTPS，憑證授權單位在你的 Mac 上製作；其他流量直接通過、不被讀取。
- HTTP/1.1、HTTP/2（含 gRPC）與 WebSocket 訊息。
- Map Local、Map Remote、中斷點、JavaScript 腳本、套用 Chrome DevTools 預設組合的限速，以及輸出 HAR。
- 選用：透明代理網路延伸功能，用於不使用系統代理伺服器的 App。

### iPhone 與 iPad

- **Mac**：透過區域網路顯示 Mac 的即時 Wi-Fi 訊號、雜訊、訊雜比與圖表。
- **這台裝置**：系統對這條 Wi-Fi 連線的品質評等（iOS 26 以上），以及每秒量測一次到路由器與網際網路的往返時間：中位數、抖動與遺失率。

iOS 不讓 App 讀取 Wi-Fi 訊號強度，所以訊號讀數來自 Mac。

## 系統需求

- Mac：macOS 26 以上。
- iPhone 與 iPad：iOS 與 iPadOS 18 以上；連結品質需要 26 以上。
- 介面語言：正體中文與英文，跟隨系統語言；其他語言顯示英文。

## 安裝

- **Mac**：從[最新版本](https://github.com/linzeyan/WiFiDetect/releases/latest)下載 `WiFiDetect.zip`，解壓縮後把 WiFiDetect 移到「應用程式」再打開。App 以 Developer ID 簽署，並經過 Apple 公證。
- **iPhone 與 iPad**：即將在 App Store 上架。

## 使用方式

### Wi-Fi

打開 WiFiDetect 就會開始量測「Wi-Fi › 訊號」。在圖表上方選擇時間範圍；「顯示網路名稱」會要求 macOS 規定的定位權限。工具列的「輸出 CSV⋯」會儲存視窗中的讀數。「Wi-Fi › 附近的網路」會掃描周圍的網路。

### 流量

讀取封包需要一個以 root 身分執行的輔助程式，只要安裝一次：

1. 「設定 › 輔助程式 › 安裝」。
2. 在「系統設定 › 一般 › 登入項目與延伸功能」中允許 WiFiDetect（按「打開登入項目」會直接帶你過去）。
3. 「流量 › 總覽 › 開始擷取」。

「流量 › 連線」列出每一條連線。「錄製 PCAP⋯」會把封包存成檔案，「檔案 › 打開擷取檔⋯」（⌘O）可以打開存好的檔案。

- 要標出每一條連線背後的 App：打開「設定 › 流量 › 以內容過濾器辨識 App」，並在 macOS 詢問時允許延伸功能與內容過濾器。
- 要看見網路上的其他裝置：打開「設定 › 流量 › 從路由器收集流量」，再把路由器的 NetFlow v9 或 IPFIX 匯出目標設為這台 Mac 的 4739 連接埠。流量會顯示在「流量 › 路由器流量」。

### HTTP(S) 除錯

1. 照上面的步驟安裝輔助程式：切換系統代理伺服器靠的就是它。
2. 「HTTP › 請求 › 啟動代理伺服器」。使用系統代理伺服器的 App 送出的請求就會出現。
3. 要讀取 HTTPS：按「設定 › 代理伺服器 › 製作並信任⋯」（macOS 會要求輸入密碼），再到「解密以下主機的 HTTPS」列出主機，例如 `api.example.com` 或 `*.example.com`。
4. Map Local、Map Remote、中斷點與腳本都在「設定 › 規則」。

「停止代理伺服器」會還原系統代理伺服器。除錯完成後，用「設定 › 代理伺服器 › 移除⋯」刪除憑證授權單位。

不使用系統代理伺服器的 App：打開「設定 › 代理伺服器 › 擷取不使用系統代理伺服器的 App」，再把它們加入清單。

### iPhone 與 iPad

1. 在 Mac 上打開「設定 › Wi-Fi › 與 iPhone 和 iPad 分享讀數」。
2. 在同一個網路上的 iPhone 或 iPad 打開 WiFiDetect，「Mac」頁面會找到這台 Mac。

網路上的任何人都能讀取 Mac 分享的內容：訊號、雜訊、頻道與傳輸速率，絕不包含網路名稱。

## 隱私權

WiFiDetect 不收集任何資料：沒有帳號、分析或廣告，所有資料都留在你的裝置與網路上。詳見 [PRIVACY.md](PRIVACY.md)。

## 從原始碼建置

以 Xcode 27.1 與 [XcodeGen](https://github.com/yonaskolb/XcodeGen) 建置。Xcode 專案由 `project.yml` 產生，不放進版本控制。

```sh
make build     # App 與輔助程式
make run       # 建置並打開
make test      # 單元測試
make ios       # iPhone 與 iPad App（模擬器）
make strings   # 把新的介面字串併入字串目錄；有未翻譯的字串就失敗
make dist      # 含網路延伸功能、經過公證的 Developer ID 版本：build/dist/WiFiDetect.zip
make release   # make dist 之後建立 GitHub release
make help      # 其他指令
```

第一次建置會把 DB-IP Lite 資料庫下載到 `App/GeoIP`。簽署使用 team `NKJSLB6HBR`：要用自己的 team 建置，請修改 `project.yml`、`Shared/HelperProtocol.swift`（輔助程式只和同一個 team 的 App 通訊）與 `scripts/dist.sh` 裡的 team，以及 `project.yml` 的 `bundleIdPrefix`。

介面字串以英文撰寫，正體中文翻譯放在各 target 的 `Localizable.xcstrings` 與 `InfoPlist.xcstrings`。命令列建置不會更新字串目錄：新增介面字串後執行 `make strings`，它會把新字串併入並列出還沒翻譯的字串。

### 發布 Mac 版

每個版本都在 Mac 上建置、公證，再發布到這裡：

1. 調高 `project.yml` 的 `MARKETING_VERSION`，commit 後 push `main`。
2. `make release`。它會確認工作目錄是乾淨的、GitHub 上的 `main` 就是要建置的 commit、這個版本還沒發布過；接著執行 `make dist`，建立 `v<版本>` release 並附上 `WiFiDetect.zip`。`NOTES="…" make release` 可以指定版本說明。

需要已登入的 `gh`、鑰匙圈裡的 Developer ID 憑證，以及 notarytool 鑰匙圈設定檔 `zeyanlin-notary`（用別的設定檔就加 `NOTARY_PROFILE=`）。

## 致謝

- [IP Geolocation by DB-IP](https://db-ip.com)，CC BY 4.0。
- [SwiftNIO](https://github.com/apple/swift-nio)、[swift-nio-ssl](https://github.com/apple/swift-nio-ssl)、[swift-nio-http2](https://github.com/apple/swift-nio-http2) 與 [swift-certificates](https://github.com/apple/swift-certificates)，Apache 2.0。

完整的第三方軟體清單與授權聲明見 [NOTICE.md](NOTICE.md)，Mac 版的 App 裡也附了一份。

## 授權

[Apache License 2.0](LICENSE)。
