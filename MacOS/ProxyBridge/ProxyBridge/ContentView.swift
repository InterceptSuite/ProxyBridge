//
//  ContentView.swift
//  ProxyBridge - GUI
//
//  Created by sourav kalal on 14/11/25.
//

import SwiftUI

struct ContentView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var selectedTab = 0
    @State private var connectionSearchText = ""
    @State private var activitySearchText = ""
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("ProxyBridge")
                    .font(.headline)
                    .padding(.leading)
                
                Spacer()
            }
            .frame(height: 44)
            .background(Color(NSColor.windowBackgroundColor))
            
            Divider()
            
            // Tab selector
            HStack(spacing: 0) {
                TabButton(
                    title: "Connections",
                    isSelected: selectedTab == 0,
                    action: { selectedTab = 0 }
                )
                
                TabButton(
                    title: "Activity Logs",
                    isSelected: selectedTab == 1,
                    action: { selectedTab = 1 }
                )
                
                Spacer()
            }
            .frame(height: 40)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Content
            if selectedTab == 0 {
                ConnectionsView(
                    connections: filteredConnections,
                    searchText: $connectionSearchText,
                    onClear: { viewModel.clearConnections() }
                )
            } else {
                ActivityLogsView(
                    logs: filteredActivityLogs,
                    searchText: $activitySearchText,
                    onClear: { viewModel.clearActivityLogs() }
                )
            }
        }
        .frame(minWidth: 800, minHeight: 600)
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
            // Search bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)
                TextField("Search connections...", text: $searchText)
                    .textFieldStyle(.plain)
                Spacer()
                Button("Clear") {
                    onClear()
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Connections list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(connections) { connection in
                            HStack(spacing: 12) {
                                Text("[\(connection.timestamp)]")
                                    .foregroundColor(.gray)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text("[\(connection.connectionProtocol)]")
                                    .foregroundColor(.blue)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text(connection.process)
                                    .foregroundColor(.green)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text("→")
                                    .foregroundColor(.gray)
                                
                                Text("\(connection.destination):\(connection.port)")
                                    .foregroundColor(.orange)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text("→")
                                    .foregroundColor(.gray)
                                
                                Text(connection.proxy)
                                    .foregroundColor(connection.proxy == "Direct" ? .gray : .purple)
                                    .font(.system(.body, design: .monospaced))
                                    .fontWeight(.medium)
                            }
                            .padding(.horizontal)
                            .padding(.vertical, 4)
                            .id(connection.id)
                        }
                    }
                    .onChange(of: connections.count) { _ in
                        if let last = connections.last {
                            withAnimation {
                                proxy.scrollTo(last.id, anchor: .bottom)
                            }
                        }
                    }
                }
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
            // Search bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)
                TextField("Search logs...", text: $searchText)
                    .textFieldStyle(.plain)
                Spacer()
                Button("Clear") {
                    onClear()
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Logs list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(logs) { log in
                            HStack(spacing: 12) {
                                Text("[\(log.timestamp)]")
                                    .foregroundColor(.gray)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text("[\(log.level)]")
                                    .foregroundColor(log.level == "ERROR" ? .red : .blue)
                                    .font(.system(.body, design: .monospaced))
                                
                                Text(log.message)
                                    .font(.system(.body, design: .monospaced))
                            }
                            .padding(.horizontal)
                            .padding(.vertical, 4)
                            .id(log.id)
                        }
                    }
                    .onChange(of: logs.count) { _ in
                        if let last = logs.last {
                            withAnimation {
                                proxy.scrollTo(last.id, anchor: .bottom)
                            }
                        }
                    }
                }
            }
        }
    }
}
