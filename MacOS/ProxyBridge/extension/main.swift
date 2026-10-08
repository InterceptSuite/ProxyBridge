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
    let maxAllowed = rl.rlim_max == RLIM_INFINITY ? target : min(target, rl.rlim_max)
    if rl.rlim_cur < maxAllowed {
        rl.rlim_cur = maxAllowed
        _ = setrlimit(RLIMIT_NOFILE, &rl)
    }
}

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
