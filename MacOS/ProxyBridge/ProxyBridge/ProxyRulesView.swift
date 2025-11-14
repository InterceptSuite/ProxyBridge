//
//  ProxyRulesView.swift
//  ProxyBridge
//
//  Created by sourav kalal on 14/11/25.
//

import SwiftUI

struct ProxyRulesView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    
    var body: some View {
        VStack {
            Text("Proxy Rules")
                .font(.title2)
                .fontWeight(.semibold)
                .padding()
            
            Spacer()
            
            Text("Coming soon...")
                .font(.title3)
                .foregroundColor(.gray)
            
            Spacer()
        }
        .frame(width: 700, height: 500)
    }
}
