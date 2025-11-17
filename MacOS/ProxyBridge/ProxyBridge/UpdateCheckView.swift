import SwiftUI
import Combine

struct UpdateCheckView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel = UpdateCheckViewModel()
    
    var body: some View {
        VStack(spacing: 20) {
            // Header
            Text("Check for Updates")
                .font(.title2)
                .fontWeight(.semibold)
            
            Divider()
            
            // Version Info
            VStack(spacing: 12) {
                HStack {
                    Text("Current Version:")
                        .fontWeight(.medium)
                    Spacer()
                    Text(viewModel.currentVersion)
                        .foregroundColor(.secondary)
                }
                
                HStack {
                    Text("Latest Version:")
                        .fontWeight(.medium)
                    Spacer()
                    Text(viewModel.latestVersion)
                        .foregroundColor(viewModel.latestVersionColor)
                }
            }
            .padding(.horizontal)
            
            // Status Message
            if !viewModel.statusMessage.isEmpty {
                HStack {
                    Image(systemName: viewModel.isUpdateAvailable ? "arrow.down.circle.fill" : "checkmark.circle.fill")
                        .foregroundColor(viewModel.statusColor)
                    Text(viewModel.statusMessage)
                        .foregroundColor(viewModel.statusColor)
                        .fontWeight(.medium)
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
            
            // Progress
            if viewModel.isChecking {
                ProgressView("Checking for updates...")
                    .padding()
            } else if viewModel.isDownloading {
                VStack(spacing: 8) {
                    ProgressView(value: viewModel.downloadProgress, total: 1.0)
                        .progressViewStyle(.linear)
                    Text(viewModel.downloadStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
            }
            
            Spacer()
            
            // Buttons
            HStack(spacing: 12) {
                if viewModel.isUpdateAvailable && !viewModel.isDownloading {
                    Button("Download Now") {
                        Task {
                            await viewModel.downloadAndInstall()
                        }
                    }
                    .controlSize(.large)
                }
                
                if !viewModel.isChecking && !viewModel.isDownloading {
                    Button("Check Again") {
                        Task {
                            await viewModel.checkForUpdates()
                        }
                    }
                }
                
                Button(viewModel.isDownloading ? "Cancel" : "Close") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(viewModel.isDownloading)
            }
        }
        .padding()
        .frame(width: 450, height: 300)
        .task {
            await viewModel.checkForUpdates()
        }
    }
}

@MainActor
class UpdateCheckViewModel: ObservableObject {
    @Published var currentVersion = ""
    @Published var latestVersion = ""
    @Published var statusMessage = ""
    @Published var statusColor = Color.secondary
    @Published var latestVersionColor = Color.secondary
    @Published var errorMessage = ""
    @Published var isChecking = false
    @Published var hasError = false
    @Published var isUpdateAvailable = false
    @Published var isDownloading = false
    @Published var downloadProgress: Double = 0
    @Published var downloadStatus = ""
    
    private let updateService = UpdateService()
    private var versionInfo: VersionInfo?
    
    func checkForUpdates() async {
        isChecking = true
        hasError = false
        statusMessage = ""
        errorMessage = ""
        
        let info = await updateService.checkForUpdates()
        versionInfo = info
        
        currentVersion = info.currentVersion
        latestVersion = info.latestVersion
        isUpdateAvailable = info.isUpdateAvailable
        
        if let error = info.error {
            hasError = true
            errorMessage = error
            statusMessage = "Unable to check for updates"
            statusColor = .red
            latestVersionColor = .red
        } else if info.isUpdateAvailable {
            statusMessage = "New version available!"
            statusColor = .green
            latestVersionColor = .green
        } else {
            statusMessage = "You have the latest version"
            statusColor = .green
            latestVersionColor = .blue
        }
        
        isChecking = false
    }
    
    func downloadAndInstall() async {
        guard let info = versionInfo,
              let downloadUrl = info.downloadUrl,
              let fileName = info.fileName else {
            errorMessage = "Download URL not available"
            hasError = true
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
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second delay
            
            updateService.installUpdateAndQuit(installerPath: installerPath)
        } catch {
            hasError = true
            errorMessage = "Download error: \(error.localizedDescription)"
            downloadStatus = "Download failed"
            isDownloading = false
        }
    }
}
