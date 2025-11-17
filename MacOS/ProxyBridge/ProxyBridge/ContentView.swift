import SwiftUI

struct ContentView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var selectedTab = 0
    @State private var connectionSearchText = ""
    @State private var activitySearchText = ""
    
    var body: some View {
        VStack(spacing: 0) {
            headerView
            Divider()
            tabSelector
            Divider()
            contentView
        }
        .frame(minWidth: 800, minHeight: 600)
    }
    
    private var headerView: some View {
        HStack {
            Text("ProxyBridge")
                .font(.headline)
                .padding(.leading)
            Spacer()
        }
        .frame(height: 44)
        .background(Color(NSColor.windowBackgroundColor))
    }
    
    private var tabSelector: some View {
        HStack(spacing: 0) {
            TabButton(title: "Connections", isSelected: selectedTab == 0) {
                selectedTab = 0
            }
            TabButton(title: "Activity Logs", isSelected: selectedTab == 1) {
                selectedTab = 1
            }
            Spacer()
        }
        .frame(height: 40)
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private var contentView: some View {
        Group {
            if selectedTab == 0 {
                ConnectionsView(
                    connections: filteredConnections,
                    searchText: $connectionSearchText,
                    onClear: viewModel.clearConnections
                )
            } else {
                ActivityLogsView(
                    logs: filteredActivityLogs,
                    searchText: $activitySearchText,
                    onClear: viewModel.clearActivityLogs
                )
            }
        }
    }
    
    private var filteredConnections: [ProxyBridgeViewModel.ConnectionLog] {
        if connectionSearchText.isEmpty {
            return viewModel.connections
        }
        return viewModel.connections.filter {
            $0.process.localizedCaseInsensitiveContains(connectionSearchText) ||
            $0.destination.localizedCaseInsensitiveContains(connectionSearchText) ||
            $0.proxy.localizedCaseInsensitiveContains(connectionSearchText)
        }
    }
    
    private var filteredActivityLogs: [ProxyBridgeViewModel.ActivityLog] {
        if activitySearchText.isEmpty {
            return viewModel.activityLogs
        }
        return viewModel.activityLogs.filter {
            $0.message.localizedCaseInsensitiveContains(activitySearchText) ||
            $0.level.localizedCaseInsensitiveContains(activitySearchText)
        }
    }
}

struct TabButton: View {
    let title: String
    let isSelected: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(isSelected ? Color.blue.opacity(0.2) : Color.clear)
                .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }
}

struct ConnectionsView: View {
    let connections: [ProxyBridgeViewModel.ConnectionLog]
    @Binding var searchText: String
    let onClear: () -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()
            connectionsList
        }
    }
    
    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.gray)
            TextField("Search connections...", text: $searchText)
                .textFieldStyle(.plain)
            Spacer()
            Button("Clear", action: onClear)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private var connectionsList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(connections) { connection in
                        connectionRow(connection)
                            .id(connection.id)
                    }
                }
                .onChange(of: connections.count) { _ in
                    scrollToLast(proxy: proxy)
                }
            }
        }
    }
    
    private func connectionRow(_ connection: ProxyBridgeViewModel.ConnectionLog) -> some View {
        HStack(spacing: 12) {
            monoText("[\(connection.timestamp)]", color: .gray)
            monoText("[\(connection.connectionProtocol)]", color: .blue)
            monoText(connection.process, color: .green)
            monoText("→", color: .gray)
            monoText("\(connection.destination):\(connection.port)", color: .orange)
            monoText("→", color: .gray)
            monoText(connection.proxy, color: connection.proxy == "Direct" ? .gray : .purple)
                .fontWeight(.medium)
        }
        .padding(.horizontal)
        .padding(.vertical, 4)
    }
    
    private func monoText(_ text: String, color: Color) -> some View {
        Text(text)
            .foregroundColor(color)
            .font(.system(.body, design: .monospaced))
    }
    
    private func scrollToLast(proxy: ScrollViewProxy) {
        if let last = connections.last {
            withAnimation {
                proxy.scrollTo(last.id, anchor: .bottom)
            }
        }
    }
}

struct ActivityLogsView: View {
    let logs: [ProxyBridgeViewModel.ActivityLog]
    @Binding var searchText: String
    let onClear: () -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()
            logsList
        }
    }
    
    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.gray)
            TextField("Search logs...", text: $searchText)
                .textFieldStyle(.plain)
            Spacer()
            Button("Clear", action: onClear)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private var logsList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(logs) { log in
                        logRow(log)
                            .id(log.id)
                    }
                }
                .onChange(of: logs.count) { _ in
                    scrollToLast(proxy: proxy)
                }
            }
        }
    }
    
    private func logRow(_ log: ProxyBridgeViewModel.ActivityLog) -> some View {
        HStack(spacing: 12) {
            monoText("[\(log.timestamp)]", color: .gray)
            monoText("[\(log.level)]", color: log.level == "ERROR" ? .red : .blue)
            monoText(log.message, color: .primary)
        }
        .padding(.horizontal)
        .padding(.vertical, 4)
    }
    
    private func monoText(_ text: String, color: Color) -> some View {
        Text(text)
            .foregroundColor(color)
            .font(.system(.body, design: .monospaced))
    }
    
    private func scrollToLast(proxy: ScrollViewProxy) {
        if let last = logs.last {
            withAnimation {
                proxy.scrollTo(last.id, anchor: .bottom)
            }
        }
    }
}
