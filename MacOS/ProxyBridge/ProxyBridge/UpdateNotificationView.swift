import SwiftUI
import Combine

struct UpdateNotificationView: View {
    @Environment(\.dismiss) private var dismiss
    let versionInfo: VersionInfo
    @StateObject private var viewModel: UpdateNotificationViewModel
    
    init(versionInfo: VersionInfo) {
        self.versionInfo = versionInfo
        _viewModel = StateObject(wrappedValue: UpdateNotificationViewModel(versionInfo: versionInfo))
    }
    
    var body: some View {
        VStack(spacing: 20) {
            // Icon and Title
            VStack(spacing: 12) {
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 50))
                    .foregroundColor(.blue)
                
                Text("Update Available")
                    .font(.title2)
                    .fontWeight(.bold)
            }
            
            Divider()
            
            // Version Information
            VStack(spacing: 10) {
                HStack {
                    Text("Current Version:")
                        .fontWeight(.medium)
                    Spacer()
                    Text(versionInfo.currentVersion)
                        .foregroundColor(.secondary)
                }
                
                HStack {
                    Text("New Version:")
                        .fontWeight(.medium)
                    Spacer()
                    Text(versionInfo.latestVersion)
                        .foregroundColor(.green)
                        .fontWeight(.semibold)
                }
            }
            .padding(.horizontal)
            
            Text("A new version of ProxyBridge is available!")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            
            // Download Progress
            if viewModel.isDownloading {
                VStack(spacing: 8) {
                    ProgressView(value: viewModel.downloadProgress, total: 1.0)
                        .progressViewStyle(.linear)
                    Text(viewModel.downloadStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
            }
            
            // Error Message
            if viewModel.hasError {
                Text(viewModel.errorMessage)
                    .foregroundColor(.red)
                    .font(.caption)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            
            Spacer()
            
            // Action Buttons
            if !viewModel.isDownloading {
                HStack(spacing: 12) {
                    Button("Don't Ask Again") {
                        viewModel.dontAskAgain()
                        dismiss()
                    }
                    
                    Button("Later") {
                        dismiss()
                    }
                    .keyboardShortcut(.cancelAction)
                    
                    Button("Update Now") {
                        Task {
                            await viewModel.downloadAndInstall()
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                }
            } else {
                Button("Cancel") {
                    dismiss()
                }
                .disabled(true)
            }
        }
        .padding()
        .frame(width: 450, height: 350)
    }
}

@MainActor
class UpdateNotificationViewModel: ObservableObject {
    @Published var downloadStatus = ""
    @Published var errorMessage = ""
    @Published var downloadProgress: Double = 0
    @Published var isDownloading = false
    @Published var hasError = false
    
    private let updateService = UpdateService()
    private let versionInfo: VersionInfo
    
    init(versionInfo: VersionInfo) {
        self.versionInfo = versionInfo
    }
    
    func downloadAndInstall() async {
        guard let downloadUrl = versionInfo.downloadUrl,
              let fileName = versionInfo.fileName else {
            hasError = true
            errorMessage = "Download URL not available"
            return
        }
        
        isDownloading = true
        downloadProgress = 0
        downloadStatus = "Starting download..."
        hasError = false
        errorMessage = ""
        
        do {
            let installerPath = try await updateService.downloadUpdate(
                from: downloadUrl,
                fileName: fileName
            ) { progress in
                Task { @MainActor in
                    self.downloadProgress = progress
                    self.downloadStatus = String(format: "Downloading... %.0f%%", progress * 100)
                }
            }
            
            downloadStatus = "Download complete. Starting installer..."
            try await Task.sleep(nanoseconds: 1_000_000_000)
            
            updateService.installUpdateAndQuit(installerPath: installerPath)
        } catch {
            hasError = true
            errorMessage = "Error downloading update: \(error.localizedDescription)"
            downloadStatus = "Download failed"
            isDownloading = false
        }
    }
    
    func dontAskAgain() {
        UserDefaults.standard.set(false, forKey: "checkForUpdatesOnStartup")
    }
}
