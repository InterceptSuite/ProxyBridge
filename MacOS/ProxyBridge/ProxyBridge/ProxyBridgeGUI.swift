//
//  ProxyBridgeGUI.swift
//  ProxyBridge - GUI App
//
//  Created by sourav kalal on 14/11/25.
//

import SwiftUI

@main
struct ProxyBridgeGUIApp: App {
    @StateObject private var viewModel = ProxyBridgeViewModel()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    init() {
        // Set the viewModel reference for AppDelegate
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
                .onAppear {
                    AppDelegate.viewModel = viewModel
                }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) { }
            
            CommandMenu("Proxy") {
                Button("Proxy Settings...") {
                    NSApp.sendAction(#selector(AppDelegate.openProxySettings), to: nil, from: nil)
                }
                .keyboardShortcut(",", modifiers: .command)
                
                Button("Proxy Rules...") {
                    NSApp.sendAction(#selector(AppDelegate.openProxyRules), to: nil, from: nil)
                }
                .keyboardShortcut("r", modifiers: .command)
            }
        }
        
        Window("Proxy Settings", id: "proxy-settings") {
            ProxySettingsView(viewModel: viewModel)
                .frame(width: 500, height: 400)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
        
        Window("Proxy Rules", id: "proxy-rules") {
            ProxyRulesView(viewModel: viewModel)
                .frame(width: 700, height: 500)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    static var viewModel: ProxyBridgeViewModel?
    
    func applicationWillTerminate(_ notification: Notification) {
        AppDelegate.viewModel?.stopProxy()
    }
    
    @objc func openProxySettings() {
        // Window opening handled by SwiftUI
    }
    
    @objc func openProxyRules() {
        // Window opening handled by SwiftUI
    }
}
