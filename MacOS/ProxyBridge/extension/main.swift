//
//  main.swift
//  extension
//
//  Created by sourav kalal on 13/11/25.
//

import Foundation
import NetworkExtension
import Darwin

// Raise the file descriptor limit from the launchd default (typically 256)
var rl = rlimit()
if getrlimit(RLIMIT_NOFILE, &rl) == 0 {
    let target = rlim_t(10240)
    if rl.rlim_cur < target {
        rl.rlim_cur = target
        if rl.rlim_max < target {
            rl.rlim_max = target
        }
        _ = setrlimit(RLIMIT_NOFILE, &rl)
    }
}

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
