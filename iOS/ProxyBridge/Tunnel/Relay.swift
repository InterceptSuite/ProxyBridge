import Foundation
import Network

/// Copies bytes both ways between two connections. All callbacks run on the one queue both connections were
/// started on, so the counter needs no lock.
enum Relay {
    private final class State {
        var finishedDirections = 0
    }

    static func pipe(_ a: NWConnection, _ b: NWConnection) {
        let state = State()
        pump(from: a, to: b, state: state)
        pump(from: b, to: a, state: state)
    }

    private static func pump(from source: NWConnection, to target: NWConnection, state: State) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if error != nil {
                source.cancel()
                target.cancel()
                return
            }
            let next = {
                if isComplete {
                    end(source: source, target: target, state: state)
                } else {
                    pump(from: source, to: target, state: state)
                }
            }
            if let data, !data.isEmpty {
                target.send(content: data, completion: .contentProcessed { error in
                    if error != nil {
                        source.cancel()
                        target.cancel()
                    } else {
                        next()
                    }
                })
            } else {
                next()
            }
        }
    }

    /// One side finished sending: pass the close on, and drop both once the other side is done too.
    private static func end(source: NWConnection, target: NWConnection, state: State) {
        target.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
        state.finishedDirections += 1
        if state.finishedDirections == 2 {
            source.cancel()
            target.cancel()
        }
    }
}
