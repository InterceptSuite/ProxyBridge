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
                    openProxySettingsWindow()
                }
                .keyboardShortcut(",", modifiers: .command)
                
                Button("Proxy Rules...") {
                    openProxyRulesWindow()
                }
                .keyboardShortcut("r", modifiers: .command)
            }
        }
        
        Window("Proxy Settings", id: "proxy-settings") {
            ProxySettingsView(viewModel: viewModel)
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
    
    private func openProxySettingsWindow() {
        NSApp.sendAction(#selector(AppDelegate.openProxySettings), to: nil, from: nil)
    }
    
    private func openProxyRulesWindow() {
        NSApp.sendAction(#selector(AppDelegate.openProxyRules), to: nil, from: nil)
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    static var viewModel: ProxyBridgeViewModel?
    
    func applicationWillTerminate(_ notification: Notification) {
        AppDelegate.viewModel?.stopProxy()
    }
    
    @objc func openProxySettings() {
        if let window = NSApplication.shared.windows.first(where: { $0.title == "Proxy Settings" }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            // Open new window
            let controller = NSHostingController(rootView: ProxySettingsView(viewModel: AppDelegate.viewModel!))
            let window = NSWindow(contentViewController: controller)
            window.title = "Proxy Settings"
            window.setContentSize(NSSize(width: 600, height: 500))
            window.styleMask = [.titled, .closable]
            window.center()
            window.makeKeyAndOrderFront(nil)
        }
    }
    
    @objc func openProxyRules() {
        if let window = NSApplication.shared.windows.first(where: { $0.title == "Proxy Rules" }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            // Open new window
            let controller = NSHostingController(rootView: ProxyRulesView(viewModel: AppDelegate.viewModel!))
            let window = NSWindow(contentViewController: controller)
            window.title = "Proxy Rules"
            window.setContentSize(NSSize(width: 1000, height: 600))
            window.styleMask = [.titled, .closable, .resizable]
            window.center()
            window.makeKeyAndOrderFront(nil)
        }
    }
}
