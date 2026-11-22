// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation
import os

/// A TCP stream backed by an opaque C handle. One receive and one send can run
/// concurrently. Overlapping receives, or overlapping sends/closeWrite calls,
/// are rejected so logical sends cannot interleave and cancellation never waits
/// behind another Swift operation. Await send before calling closeWrite.
public final class Connection: Sendable {
    public let remoteAddress: String?
    public let localAddress: String?
    public let localPort: UInt16?
    /// The key the tunnel authenticated the other end by: the dialing client's
    /// for an accepted connection, the server's for a dialed one. nil when the
    /// server did not know the remote address. It is recorded at accept time,
    /// so it stays set after ``TailcatServer/deny(_:)``.
    public let peerKey: NodePublicKey?
    private let handle: Handle
    private let state = OSAllocatedUnfairLock(initialState: State())

    private struct State: Sendable {
        var reading = false
        var writing = false
        var eof = false
        var pendingError: (any Error)?
    }

    private init(handle: Handle, info: ResourceInfo, peerKey: NodePublicKey?) {
        self.handle = handle
        self.remoteAddress = info.remoteAddress
        self.localAddress = info.localAddress
        self.localPort = info.localPort
        self.peerKey = peerKey
    }

    /// Called on a C worker. Metadata lookup can fail after a successful dial or
    /// accept, so that failure must still release the newly returned handle.
    /// A connection's tc_info never blocks, so it is read with TC_NO_CANCEL: a
    /// deadline that expires right after the dial or accept doesn't discard it.
    static func adopt(_ raw: UInt64) throws -> Connection {
        do {
            let info = try CAPI.info(raw, UInt64(TC_NO_CANCEL))
            var peerKey: NodePublicKey?
            if let text = info.peerPublicKey {
                guard let key = NodePublicKey(rawValue: text) else {
                    throw TailcatError.internalError("connection peer key is not a node key")
                }
                peerKey = key
            }
            return Connection(handle: Handle(raw), info: info, peerKey: peerKey)
        } catch {
            _ = tc_close(raw, nil)
            throw error
        }
    }

    /// Returns available bytes up to maxLength, or empty Data at TCP EOF.
    /// Cancellation/timeout leaves the connection usable. Bytes returned with
    /// an error are delivered first; the next receive reports that error.
    public func receive(maxLength: Int = 65_536, timeout: Duration? = nil) async throws -> Data {
        guard maxLength > 0 else { throw TailcatError.invalidArgument("maxLength must be positive") }
        let raw = try handle.value()
        try Task.checkCancellation()
        try state.withLock { state in
            guard !state.reading else { throw TailcatError.invalidArgument("a receive is already in progress") }
            state.reading = true
        }
        defer { state.withLock { $0.reading = false } }
        return try await Blocking.run(timeout: timeout) { [state] token in
            let eof = try state.withLock { state in
                if let error = state.pendingError {
                    state.pendingError = nil
                    throw error
                }
                return state.eof
            }
            if eof { return Data() }
            var data = Data(count: maxLength)
            var count = 0
            var message: UnsafeMutablePointer<CChar>?
            let status = data.withUnsafeMutableBytes {
                tc_conn_read(raw, token, $0.baseAddress, $0.count, &count, &message)
            }
            let text = CAPI.take(message)
            let error = status == TC_EOF ? nil : CAPI.error(status, text)
            if status == TC_EOF { state.withLock { $0.eof = true } }
            if count > 0 {
                data.count = count
                state.withLock { $0.pendingError = error }
                return data
            }
            if let error { throw error }
            return Data()
        }
    }

    /// Sends all bytes under one deadline. A failure after any bytes were sent
    /// throws PartialWriteError with their count; cancellation cannot undo them.
    public func send(_ data: Data, timeout: Duration? = nil) async throws {
        let raw = try handle.value()
        try beginWrite()
        defer { state.withLock { $0.writing = false } }
        try await Blocking.run(timeout: timeout) { token in
            var written = 0
            do {
                try data.withUnsafeBytes { bytes in
                    while written < bytes.count {
                        var count = 0
                        var message: UnsafeMutablePointer<CChar>?
                        let status = tc_conn_write(raw, token,
                            UnsafeMutableRawPointer(mutating: bytes.baseAddress!.advanced(by: written)),
                            bytes.count - written, &count, &message)
                        written += count
                        if let error = CAPI.error(status, CAPI.take(message)) { throw error }
                        guard count > 0 else { throw TailcatError.internalError("C write made no progress") }
                    }
                }
            } catch {
                if written > 0 { throw PartialWriteError(bytesWritten: written, underlyingError: error) }
                throw error
            }
        }
    }

    /// Sends FIN, retaining the ability to receive a reply. Await prior sends
    /// first; overlapping write operations throw invalidArgument.
    public func closeWrite(timeout: Duration? = nil) async throws {
        let raw = try handle.value()
        try beginWrite()
        defer { state.withLock { $0.writing = false } }
        try await Blocking.run(timeout: timeout) { token in
            try CAPI.check { tc_conn_close_write(raw, token, $0) }
        }
    }

    private func beginWrite() throws {
        try Task.checkCancellation()
        try state.withLock { state in
            guard !state.writing else { throw TailcatError.invalidArgument("a write is already in progress") }
            state.writing = true
        }
    }

    public var incoming: AsyncThrowingStream<Data, any Error> {
        AsyncThrowingStream(unfolding: { [self] in
            let data = try await receive()
            return data.isEmpty ? nil : data
        })
    }

    /// Interrupts pending reads/writes and waits for teardown off-thread.
    public func close() async { await handle.close() }
}
