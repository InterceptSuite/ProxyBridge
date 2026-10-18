import Foundation
import AppKit

// the update manifest served at download.interceptsuite.com, one entry per platform
struct UpdateManifest: Codable {
    let macos: PlatformRelease
}

struct PlatformRelease: Codable {
    let version: String
    let releaseDate: String
    let download: String
    let releaseNotes: String

    enum CodingKeys: String, CodingKey {
        case version
        case releaseDate = "release_date"
        case download
        case releaseNotes = "release_notes"
    }
}

struct VersionInfo {
    let currentVersion: String
    let latestVersion: String
    let isUpdateAvailable: Bool
    let downloadUrl: String?
    let fileName: String?
    let releaseNotesUrl: String?
    let error: String?
}

// completes the async download exactly once, whichever callback fires first
private final class DownloadDelegate: NSObject, URLSessionDownloadDelegate {
    var continuation: CheckedContinuation<URL, Error>?
    private let destination: URL
    private let progress: (Double) -> Void
    private var lastReported = 0.0
    private var finished = false
    private let lock = NSLock()

    init(destination: URL, progress: @escaping (Double) -> Void) {
        self.destination = destination
        self.progress = progress
    }

    private func finish(_ result: Result<URL, Error>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(with: result)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        guard totalBytesExpectedToWrite > 0 else { return }
        let value = Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)
        // at most ~100 updates over the whole download
        if value - lastReported >= 0.01 || value >= 1 {
            lastReported = value
            DispatchQueue.main.async { self.progress(value) }
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard let http = downloadTask.response as? HTTPURLResponse, http.statusCode == 200 else {
            finish(.failure(NSError(domain: "UpdateService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Download failed"])))
            return
        }
        do {
            // the temp file is deleted as soon as this returns, so move it now
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: location, to: destination)
            DispatchQueue.main.async { self.progress(1.0) }
            finish(.success(destination))
        } catch {
            finish(.failure(error))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error { finish(.failure(error)) }
    }
}

class UpdateService {
    private let manifestUrl = "https://download.interceptsuite.com/proxybridge.json"

    func checkForUpdates() async -> VersionInfo {
        do {
            guard let url = URL(string: manifestUrl) else {
                return errorVersion("Invalid update URL")
            }

            var request = URLRequest(url: url)
            request.setValue("ProxyBridge-UpdateChecker", forHTTPHeaderField: "User-Agent")
            request.cachePolicy = .reloadIgnoringLocalCacheData

            let (data, _) = try await URLSession.shared.data(for: request)
            let manifest = try JSONDecoder().decode(UpdateManifest.self, from: data)

            let mac = manifest.macos
            let currentVersion = getCurrentVersion()
            let fileName = URL(string: mac.download)?.lastPathComponent ?? "ProxyBridge-Installer.pkg"
            let isUpdateAvailable = isNewerVersion(mac.version, currentVersion)
                && mac.download.lowercased().hasSuffix(".pkg")

            return VersionInfo(
                currentVersion: currentVersion,
                latestVersion: "v\(mac.version)",
                isUpdateAvailable: isUpdateAvailable,
                downloadUrl: mac.download,
                fileName: fileName,
                releaseNotesUrl: mac.releaseNotes,
                error: nil
            )
        } catch {
            return errorVersion("Failed to check for updates: \(error.localizedDescription)")
        }
    }

    func downloadUpdate(from urlString: String, fileName: String, progress: @escaping (Double) -> Void) async throws -> URL {
        guard let url = URL(string: urlString) else {
            throw NSError(domain: "UpdateService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid download URL"])
        }

        // only ever the last path component, so a crafted name can't leave the temp folder
        var safeName = URL(fileURLWithPath: fileName).lastPathComponent
        if safeName.isEmpty || safeName == "." || safeName == ".." { safeName = "ProxyBridge-Installer.pkg" }
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(safeName)

        // a download task streams to disk in the system's own buffers. the old loop
        // walked the file one byte at a time through an async sequence, which burned
        // a core for the whole download and held the entire pkg in memory
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForResource = 900
        let delegate = DownloadDelegate(destination: fileURL, progress: progress)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        var request = URLRequest(url: url, timeoutInterval: 30)
        request.setValue("ProxyBridge-UpdateChecker", forHTTPHeaderField: "User-Agent")

        return try await withCheckedThrowingContinuation { continuation in
            delegate.continuation = continuation
            session.downloadTask(with: request).resume()
        }
    }

    func installUpdateAndQuit(installerPath: URL) {
        NSWorkspace.shared.open(installerPath)
        // let the installer come up before we quit
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            NSApplication.shared.terminate(nil)
        }
    }

    private func getCurrentVersion() -> String {
        if let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
            return "v\(version)"
        }
        return "v4.1.0"
    }

    private func isNewerVersion(_ latest: String, _ current: String) -> Bool {
        let latestComponents = latest.split(separator: ".").compactMap { Int($0) }
        let currentVersionString = current.hasPrefix("v") ? String(current.dropFirst()) : current
        let currentComponents = currentVersionString.split(separator: ".").compactMap { Int($0) }

        for i in 0..<min(latestComponents.count, currentComponents.count) {
            if latestComponents[i] > currentComponents[i] {
                return true
            } else if latestComponents[i] < currentComponents[i] {
                return false
            }
        }

        return latestComponents.count > currentComponents.count
    }

    private func errorVersion(_ message: String) -> VersionInfo {
        return VersionInfo(
            currentVersion: getCurrentVersion(),
            latestVersion: "Error",
            isUpdateAvailable: false,
            downloadUrl: nil,
            fileName: nil,
            releaseNotesUrl: nil,
            error: message
        )
    }
}
