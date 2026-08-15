import Cocoa
import Foundation
import Security
import SQLite3

// MARK: - CommonCrypto (always linked on macOS, just need the types)

@_silgen_name("CCCrypt")
func CCCrypt_raw(
    _ op: UInt32, _ alg: UInt32, _ opts: UInt32,
    _ key: UnsafeRawPointer, _ keyLen: Int,
    _ iv: UnsafeRawPointer?,
    _ dataIn: UnsafeRawPointer, _ dataInLen: Int,
    _ dataOut: UnsafeMutableRawPointer, _ dataOutAvail: Int,
    _ dataOutMoved: UnsafeMutablePointer<Int>
) -> Int32

@_silgen_name("CCKeyDerivationPBKDF")
func CCKeyDerivationPBKDF_raw(
    _ algorithm: UInt32,
    _ password: UnsafePointer<Int8>, _ passwordLen: Int,
    _ salt: UnsafePointer<UInt8>, _ saltLen: Int,
    _ prf: UInt32, _ rounds: UInt32,
    _ derivedKey: UnsafeMutablePointer<UInt8>, _ derivedKeyLen: Int
) -> Int32

private let kCCDecrypt_v: UInt32 = 1
private let kCCAlgorithmAES_v: UInt32 = 0
private let kCCOptionPKCS7Padding_v: UInt32 = 1
private let kCCPBKDF2_v: UInt32 = 2
private let kCCPRFHmacAlgSHA1_v: UInt32 = 1
private let kCCBlockSizeAES128_v = 16
private let kCCSuccess_v: Int32 = 0

// MARK: - Models

struct UsageResponse: Codable {
    let fiveHour: Period?
    let sevenDay: Period?
    let extraUsage: ExtraUsage?

    enum CodingKeys: String, CodingKey {
        case fiveHour = "five_hour"
        case sevenDay = "seven_day"
        case extraUsage = "extra_usage"
    }
}

struct ExtraUsage: Codable {
    let isEnabled: Bool
    let monthlyLimit: Double?
    let usedCredits: Double?
    let utilization: Double?
    let currency: String?

    enum CodingKeys: String, CodingKey {
        case isEnabled = "is_enabled"
        case monthlyLimit = "monthly_limit"
        case usedCredits = "used_credits"
        case utilization
        case currency
    }

    var symbol: String {
        switch currency?.uppercased() {
        case "EUR": return "€"
        case "USD": return "$"
        case "GBP": return "£"
        default: return currency ?? ""
        }
    }

    var pctRemaining: Int {
        guard let u = utilization else { return 100 }
        return max(0, 100 - Int(u))
    }

    // Returns e.g. "€2.40 / €8.00"
    var summary: String {
        let sym = symbol
        let used = usedCredits.map { String(format: "%@%.2f", sym, $0) } ?? "—"
        let limit = monthlyLimit.map { String(format: "%@%.2f", sym, $0) } ?? "—"
        return "\(used) / \(limit)"
    }
}

struct Period: Codable {
    let utilization: Double
    let resetsAt: String?

    enum CodingKeys: String, CodingKey {
        case utilization
        case resetsAt = "resets_at"
    }

    var resetDate: Date? {
        guard let s = resetsAt else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    var resetCountdown: String {
        guard let d = resetDate else { return "—" }
        let secs = d.timeIntervalSinceNow
        if secs <= 0 { return "сейчас" }
        let h = Int(secs) / 3600
        let m = (Int(secs) % 3600) / 60
        if h > 0 { return "\(h)ч \(m)м" }
        return "\(m)м"
    }

    var pctRemaining: Int { max(0, 100 - Int(utilization)) }
}

// MARK: - Credential Extractor

struct Credentials {
    let orgId: String
    let sessionKey: String
}

func extractCredentials() -> Credentials? {
    let cookiesURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Claude/Cookies")

    guard FileManager.default.fileExists(atPath: cookiesURL.path) else { return nil }

    let tmpURL = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString + ".db")
    guard (try? FileManager.default.copyItem(at: cookiesURL, to: tmpURL)) != nil else { return nil }
    defer { try? FileManager.default.removeItem(at: tmpURL) }

    var db: OpaquePointer?
    guard sqlite3_open(tmpURL.path, &db) == SQLITE_OK else { return nil }
    defer { sqlite3_close(db) }

    let sessionKey = readCookie(db: db, name: "sessionKey")
    let orgId = readCookie(db: db, name: "lastActiveOrg")

    guard let sk = sessionKey, let oid = orgId, !sk.isEmpty, !oid.isEmpty else { return nil }
    return Credentials(orgId: oid, sessionKey: sk)
}

private func readCookie(db: OpaquePointer?, name: String) -> String? {
    let sql = """
    SELECT value, encrypted_value FROM cookies
    WHERE name = '\(name)' AND host_key LIKE '%claude.ai%'
    ORDER BY creation_utc DESC LIMIT 1
    """
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
    defer { sqlite3_finalize(stmt) }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

    // Try plain-text value first
    if let ptr = sqlite3_column_text(stmt, 0) {
        let v = String(cString: ptr)
        if !v.isEmpty { return v }
    }

    // Try encrypted value (Electron/Chrome v10 format)
    guard let blob = sqlite3_column_blob(stmt, 1) else { return nil }
    let len = Int(sqlite3_column_bytes(stmt, 1))
    guard len > 3 else { return nil }
    let data = Data(bytes: blob, count: len)
    return decryptChromeCookie(data)
}

private func decryptChromeCookie(_ data: Data) -> String? {
    guard data.prefix(3) == Data([0x76, 0x31, 0x30]) else { return nil } // "v10"
    guard let pwData = keychainPassword() else { return nil }
    guard let derivedKey = pbkdf2(password: pwData) else { return nil }

    let cipher = Data(data.dropFirst(3))
    let iv = Data(repeating: 0x20, count: kCCBlockSizeAES128_v)

    var out = Data(count: cipher.count + kCCBlockSizeAES128_v)
    let outCapacity = out.count
    var moved = 0
    let status = out.withUnsafeMutableBytes { outPtr in
        cipher.withUnsafeBytes { inPtr in
            derivedKey.withUnsafeBytes { kPtr in
                iv.withUnsafeBytes { ivPtr in
                    CCCrypt_raw(
                        kCCDecrypt_v, kCCAlgorithmAES_v, kCCOptionPKCS7Padding_v,
                        kPtr.baseAddress!, derivedKey.count,
                        ivPtr.baseAddress!,
                        inPtr.baseAddress!, cipher.count,
                        outPtr.baseAddress!, outCapacity, &moved
                    )
                }
            }
        }
    }
    guard status == kCCSuccess_v else { return nil }
    out.count = moved

    // Newer Chrome may prepend a 32-byte SHA256 tag — strip it if needed
    if out.count > 32, let s = String(data: out.dropFirst(32), encoding: .utf8), !s.isEmpty { return s }
    return String(data: out, encoding: .utf8)
}

private func keychainPassword() -> Data? {
    let candidates: [(String, String)] = [
        ("Claude Safe Storage", "Claude Key"),
        ("Chromium Safe Storage", "Chromium"),
        ("Electron Safe Storage", "Electron")
    ]
    for (service, account) in candidates {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        if SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess,
           let d = result as? Data { return d }
    }
    return nil
}

private func pbkdf2(password: Data) -> Data? {
    let salt = Data("saltysalt".utf8)
    var key = Data(count: 16)
    let r = key.withUnsafeMutableBytes { kPtr in
        password.withUnsafeBytes { pPtr in
            salt.withUnsafeBytes { sPtr in
                CCKeyDerivationPBKDF_raw(
                    kCCPBKDF2_v,
                    pPtr.baseAddress!.assumingMemoryBound(to: Int8.self), password.count,
                    sPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                    kCCPRFHmacAlgSHA1_v, 1003,
                    kPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), 16
                )
            }
        }
    }
    return r == kCCSuccess_v ? key : nil
}

// MARK: - AppDelegate

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var timer: Timer?
    var creds: Credentials?
    var lastUpdated: Date?
    var lastRaw: String = ""

    func applicationDidFinishLaunching(_ n: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "⟳"
        setLoadingMenu()
        fetchAndUpdate()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.fetchAndUpdate()
        }
    }

    func fetchAndUpdate() {
        // Re-extract credentials each cycle (cookies can refresh)
        creds = extractCredentials()
        guard let creds = creds else {
            DispatchQueue.main.async { [weak self] in
                self?.statusItem.button?.title = "🔑 Нет сессии"
                self?.setErrorMenu(msg: "Открой Claude Desktop и войди в claude.ai")
            }
            return
        }

        let url = URL(string: "https://claude.ai/api/organizations/\(creds.orgId)/usage")!
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        req.setValue("sessionKey=\(creds.sessionKey)", forHTTPHeaderField: "Cookie")
        req.setValue("web_claude_ai", forHTTPHeaderField: "anthropic-client-platform")
        req.setValue("1.0.0", forHTTPHeaderField: "anthropic-client-version")
        req.setValue("application/json", forHTTPHeaderField: "accept")

        URLSession.shared.dataTask(with: req) { [weak self] data, resp, _ in
            guard let self = self else { return }

            let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if let data = data, status == 200,
               let usage = try? JSONDecoder().decode(UsageResponse.self, from: data) {
                // Store raw for debug menu
                let raw = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
                    .flatMap { d -> String? in
                        let fh = (d["five_hour"] as? [String: Any])?["utilization"]
                        let sd = (d["seven_day"] as? [String: Any])?["utilization"]
                        guard fh != nil || sd != nil else { return nil }
                        return "5h:\(fh ?? "–")  7d:\(sd ?? "–")"
                    } ?? "no five_hour/seven_day fields"
                DispatchQueue.main.async { self.lastRaw = raw; self.updateUI(usage) }
            } else {
                self.creds = nil
                let errStr = "HTTP \(status)"
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.lastRaw = errStr
                    let cur = self.statusItem.button?.title ?? ""
                    if !cur.hasPrefix("⚠️") {
                        self.statusItem.button?.title = "⚠️ " + cur
                    }
                }
            }
        }.resume()
    }

    func updateUI(_ usage: UsageResponse) {
        lastUpdated = Date()
        let fh = usage.fiveHour
        let sd = usage.sevenDay

        let sPct = fh?.pctRemaining ?? 0
        let wPct = sd?.pctRemaining ?? 0
        let resetIn = fh?.resetCountdown ?? "—"

        func icon(_ p: Int) -> String { p > 50 ? "🟢" : p > 20 ? "🟡" : "🔴" }
        statusItem.button?.title = "\(icon(wPct))W:\(wPct)%  \(icon(sPct))H:\(sPct)%  ⏱\(resetIn)"

        let menu = NSMenu()

        // 5-hour session
        let s = NSMenuItem()
        let sFill = filled(pct: 100 - sPct)
        s.title = "5ч сессия:  [\(sFill)]  \(sPct)%"
        s.isEnabled = false
        menu.addItem(s)

        if let fh = fh {
            let sub = NSMenuItem()
            sub.title = "    Сброс через: \(fh.resetCountdown)"
            sub.isEnabled = false
            menu.addItem(sub)
        }

        menu.addItem(NSMenuItem.separator())

        // Weekly
        let w = NSMenuItem()
        let wFill = filled(pct: 100 - wPct)
        w.title = "Неделя:        [\(wFill)]  \(wPct)%"
        w.isEnabled = false
        menu.addItem(w)

        if let sd = sd {
            let sub = NSMenuItem()
            sub.title = "    Сброс через: \(sd.resetCountdown)"
            sub.isEnabled = false
            menu.addItem(sub)
        }

        menu.addItem(NSMenuItem.separator())

        let refreshItem = NSMenuItem(title: "Обновить", action: #selector(manualRefresh), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)

        // Debug info
        if !lastRaw.isEmpty {
            let dbg = NSMenuItem(title: "API: \(lastRaw)", action: nil, keyEquivalent: "")
            dbg.isEnabled = false
            menu.addItem(dbg)
        }
        if let ts = lastUpdated {
            let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
            let upd = NSMenuItem(title: "Обновлено: \(f.string(from: ts))", action: nil, keyEquivalent: "")
            upd.isEnabled = false
            menu.addItem(upd)
        }

        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        statusItem.menu = menu
    }

    private func filled(pct: Int) -> String {
        let n = min(10, max(0, pct * 10 / 100))
        return String(repeating: "█", count: n) + String(repeating: "░", count: 10 - n)
    }

    func setLoadingMenu() {
        let menu = NSMenu()
        let item = NSMenuItem(title: "Загружаю...", action: nil, keyEquivalent: "")
        item.isEnabled = false
        menu.addItem(item)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        statusItem.menu = menu
    }

    func setErrorMenu(msg: String) {
        let menu = NSMenu()
        let item = NSMenuItem(title: msg, action: nil, keyEquivalent: "")
        item.isEnabled = false
        menu.addItem(item)
        menu.addItem(NSMenuItem.separator())
        let refreshItem = NSMenuItem(title: "Повторить", action: #selector(manualRefresh), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)
        menu.addItem(withTitle: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        statusItem.menu = menu
    }

    @objc func manualRefresh() { fetchAndUpdate() }
}

// MARK: - Entry point

let app = NSApplication.shared
NSApp.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
