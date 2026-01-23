import Foundation
import AppKit

struct GitHubRelease: Codable {
    let tagName: String
    let name: String
    let prerelease: Bool
    let publishedAt: String
    let assets: [GitHubAsset]

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case name
        case prerelease
        case publishedAt = "published_at"
        case assets
    }
}

struct GitHubAsset: Codable {
    let name: String
    let browserDownloadUrl: String
    let size: Int64

    enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadUrl = "browser_download_url"
        case size
    }
}

struct VersionInfo {
    let currentVersion: String
    let latestVersion: String
    let isUpdateAvailable: Bool
    let downloadUrl: String?
    let fileName: String?
    let error: String?
}

class UpdateService {
    private let githubApiUrl = "https://api.github.com/repos/InterceptSuite/ProxyBridge/releases/latest"

    func checkForUpdates() async -> VersionInfo {
        do {
            guard let url = URL(string: githubApiUrl) else {
                return errorVersion("Invalid API URL")
            }

            var request = URLRequest(url: url)
            request.setValue("ProxyBridge-UpdateChecker", forHTTPHeaderField: "User-Agent")

            let (data, _) = try await URLSession.shared.data(for: request)
            let release = try JSONDecoder().decode(GitHubRelease.self, from: data)

            let currentVersion = getCurrentVersion()
            let latestVersion = parseVersion(release.tagName)

            // Find the PKG installer in assets
            let pkgAsset = release.assets.first { asset in
                asset.name.lowercased().hasSuffix(".pkg") &&
                (asset.name.lowercased().contains("proxybridge") ||
                 asset.name.lowercased().contains("installer"))
            }

            return VersionInfo(
                currentVersion: currentVersion,
                latestVersion: release.tagName,
                isUpdateAvailable: isNewerVersion(latestVersion, currentVersion),
                downloadUrl: pkgAsset?.browserDownloadUrl,
                fileName: pkgAsset?.name,
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

        let (asyncBytes, response) = try await URLSession.shared.bytes(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw NSError(domain: "UpdateService", code: -1, userInfo: [NSLocalizedDescriptionKey: "Download failed"])
        }

        let totalBytes = response.expectedContentLength
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent(fileName)

        // Remove existing file if any
        try? FileManager.default.removeItem(at: fileURL)

        var downloadedBytes: Int64 = 0
        let data = NSMutableData()

        for try await byte in asyncBytes {
            var byteValue = byte
            data.append(&byteValue, length: 1)
            downloadedBytes += 1

            if totalBytes > 0 {
                let progressValue = Double(downloadedBytes) / Double(totalBytes)
                await MainActor.run {
                    progress(progressValue)
                }
            }
        }

        try data.write(to: fileURL)
        return fileURL
    }

    func installUpdateAndQuit(installerPath: URL) {
        // Open the PKG installer
        NSWorkspace.shared.open(installerPath)

        // Give the installer a moment to start, then quit
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            NSApplication.shared.terminate(nil)
        }
    }

    private func getCurrentVersion() -> String {
        if let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
            return "v\(version)"
        }
        return "v3.1"
    }

    private func parseVersion(_ tagName: String) -> String {
        return tagName.hasPrefix("v") ? String(tagName.dropFirst()) : tagName
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
            error: message
        )
    }
}
