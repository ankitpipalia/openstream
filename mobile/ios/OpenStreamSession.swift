import Foundation

// Import the module that exposes openstream_client.h in the Xcode target. The
// module name is project-specific; a bridging header can be used instead.
import OpenStreamFFI

public final class OpenStreamSession {
    public struct Callbacks {
        public var ready: (UInt16, UInt16, UInt16) -> Void
        public var video: (Data, Bool, UInt64) -> Void
        public var audio: ([Int16], UInt64) -> Void
        public var rumble: (UInt32, UInt8, UInt8) -> Void
        public var error: (Int32) -> Void

        public init(
            ready: @escaping (UInt16, UInt16, UInt16) -> Void,
            video: @escaping (Data, Bool, UInt64) -> Void,
            audio: @escaping ([Int16], UInt64) -> Void,
            rumble: @escaping (UInt32, UInt8, UInt8) -> Void = { _, _, _ in },
            error: @escaping (Int32) -> Void
        ) {
            self.ready = ready
            self.video = video
            self.audio = audio
            self.rumble = rumble
            self.error = error
        }
    }

    private final class Context {
        let callbacks: Callbacks

        init(_ callbacks: Callbacks) {
            self.callbacks = callbacks
        }
    }

    private var handle: UnsafeMutablePointer<OpenStreamClient>?
    private var context: Context?
    /// The C ABI handle is not reference counted. Serialize calls that borrow
    /// it, and clear the stored pointer before stopping so a concurrent UI or
    /// callback task cannot enter freed native state. The native stop call is
    /// made outside the lock because user callbacks are allowed to call stop
    /// reentrantly from the Rust worker thread.
    private let lifecycleLock = NSLock()

    public init(origin: String, pairingJSON: String, callbacks: Callbacks) {
        self.init(
            origin: origin,
            pairingJSON: pairingJSON,
            iceURLs: nil,
            turnUsername: nil,
            turnPassword: nil,
            callbacks: callbacks
        )
    }

    /// Create a client using ICE/TURN settings loaded from secure storage.
    /// Credentials are passed separately from the URL list and pairing JSON.
    public init(
        origin: String,
        pairingJSON: String,
        iceURLs: String,
        turnUsername: String? = nil,
        turnPassword: String? = nil,
        callbacks: Callbacks
    ) {
        self.init(
            origin: origin,
            pairingJSON: pairingJSON,
            iceURLs: iceURLs,
            turnUsername: turnUsername,
            turnPassword: turnPassword,
            callbacks: callbacks,
            useExplicitICE: true
        )
    }

    private init(
        origin: String,
        pairingJSON: String,
        iceURLs: String?,
        turnUsername: String?,
        turnPassword: String?,
        callbacks: Callbacks,
        useExplicitICE: Bool = false
    ) {
        let context = Context(callbacks)
        self.context = context
        let opaque = Unmanaged.passUnretained(context).toOpaque()
        var table = OpenStreamCallbacks(
            context: opaque,
            on_ready: Self.ready,
            on_video: Self.video,
            on_audio: Self.audio,
            on_rumble: Self.rumble,
            on_error: Self.error
        )
        var originBytes = Array(origin.utf8)
        var pairingBytes = Array(pairingJSON.utf8)
        if useExplicitICE, let iceURLs {
            var iceURLBytes = Array(iceURLs.utf8)
            var usernameBytes = Array((turnUsername ?? "").utf8)
            var passwordBytes = Array((turnPassword ?? "").utf8)
            self.handle = originBytes.withUnsafeMutableBytes { originBuffer in
                pairingBytes.withUnsafeMutableBytes { pairingBuffer in
                    iceURLBytes.withUnsafeMutableBytes { iceURLBuffer in
                        usernameBytes.withUnsafeMutableBytes { usernameBuffer in
                            passwordBytes.withUnsafeMutableBytes { passwordBuffer in
                                openstream_client_start_with_ice(
                                    originBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    originBuffer.count,
                                    pairingBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    pairingBuffer.count,
                                    iceURLBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    iceURLBuffer.count,
                                    turnUsername == nil
                                        ? nil
                                        : usernameBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    turnUsername == nil ? 0 : usernameBuffer.count,
                                    turnPassword == nil
                                        ? nil
                                        : passwordBuffer.bindMemory(to: UInt8.self).baseAddress,
                                    turnPassword == nil ? 0 : passwordBuffer.count,
                                    table
                                )
                            }
                        }
                    }
                }
            }
        } else {
            self.handle = originBytes.withUnsafeMutableBytes { originBuffer in
                pairingBytes.withUnsafeMutableBytes { pairingBuffer in
                    openstream_client_start(
                        originBuffer.bindMemory(to: UInt8.self).baseAddress,
                        originBuffer.count,
                        pairingBuffer.bindMemory(to: UInt8.self).baseAddress,
                        pairingBuffer.count,
                        table
                    )
                }
            }
        }
        if self.handle == nil {
            self.context = nil
        }
    }

    deinit {
        stop()
    }

    public func sendInput(_ payload: Data) -> Int32 {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard let handle else { return -1 }
        return payload.withUnsafeBytes { buffer in
            openstream_client_send_input(
                handle,
                buffer.bindMemory(to: UInt8.self).baseAddress,
                buffer.count
            )
        }
    }

    public func stop() {
        lifecycleLock.lock()
        guard let handle else {
            lifecycleLock.unlock()
            return
        }
        // Invalidate the Swift-side capability before native teardown. Any
        // concurrent setter/input call now returns without borrowing it.
        self.handle = nil
        lifecycleLock.unlock()
        openstream_client_stop(handle)
        lifecycleLock.lock()
        context = nil
        lifecycleLock.unlock()
    }

    /// Suspend (`true`) or resume (`false`) media callbacks for scene
    /// background/foreground transitions. The session and its ACKs survive
    /// while decoder/audio callbacks and input are dropped. Returns the
    /// bridge status code, or -1 without a live handle.
    @discardableResult
    public func setPaused(_ paused: Bool) -> Int32 {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard let handle else { return -1 }
        return openstream_client_set_paused(handle, paused ? 1 : 0)
    }

    /// Forward `ProcessInfo.thermalState` (nominal/fair/serious/critical map
    /// to 0-3) so the worker sheds decode load before the OS intervenes.
    /// Returns the bridge status code, or -1 without a live handle.
    @discardableResult
    public func setThermalLevel(_ level: UInt8) -> Int32 {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        guard let handle else { return -1 }
        return openstream_client_set_thermal(handle, level)
    }

    private static let ready: @convention(c) (
        UnsafeMutableRawPointer?, UInt16, UInt16, UInt16
    ) -> Void = { opaque, width, height, fps in
        guard let opaque else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        context.callbacks.ready(width, height, fps)
    }

    private static let video: @convention(c) (
        UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, Bool, UInt64
    ) -> Void = { opaque, bytes, length, keyframe, timestamp in
        guard let opaque, let bytes, length >= 0 else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        context.callbacks.video(Data(bytes: bytes, count: length), keyframe, timestamp)
    }

    private static let audio: @convention(c) (
        UnsafeMutableRawPointer?, UnsafePointer<Int16>?, Int, UInt64
    ) -> Void = { opaque, pcm, count, timestamp in
        guard let opaque, let pcm, count >= 0 else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        let samples = Array(UnsafeBufferPointer(start: pcm, count: count))
        context.callbacks.audio(samples, timestamp)
    }

    private static let error: @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void = {
        opaque, code in
        guard let opaque else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        context.callbacks.error(code)
    }

    private static let rumble: @convention(c) (
        UnsafeMutableRawPointer?, UInt32, UInt8, UInt8
    ) -> Void = { opaque, deviceID, strong, weak in
        guard let opaque else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        context.callbacks.rumble(deviceID, strong, weak)
    }
}
