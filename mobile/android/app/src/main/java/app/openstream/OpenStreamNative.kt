package app.openstream

/**
 * Small JNI-facing API for the client-only OpenStream Rust bridge.
 *
 * The callbacks are invoked from the Rust worker thread. Implementations must
 * copy video/audio buffers immediately and marshal decoder/audio work onto the
 * Android-owned threads.
 */
object OpenStreamNative {
    init {
        System.loadLibrary("openstream_jni")
    }

    class Callbacks {
        open fun onReady(width: Int, height: Int, fps: Int) {}
        open fun onVideo(bytes: ByteArray, keyframe: Boolean, presentationTimeUs: Long) {}
        open fun onAudio(pcm: ShortArray, presentationTimeUs: Long) {}
        open fun onRumble(deviceId: Int, strong: Byte, weak: Byte) {}
        open fun onError(code: Int) {}
    }

    @JvmStatic
    external fun nativeStart(origin: String, pairingJson: String, callbacks: Callbacks): Long

    /**
     * Start using ICE/TURN settings loaded by the app from secure storage.
     * Credentials are intentionally separate from the URL list and pairing
     * JSON. A null username/password is valid for STUN-only configuration.
     */
    @JvmStatic
    external fun nativeStartWithIce(
        origin: String,
        pairingJson: String,
        iceUrls: String,
        turnUsername: String?,
        turnPassword: String?,
        callbacks: Callbacks,
    ): Long

    @JvmStatic
    external fun nativeSendInput(handle: Long, payload: ByteArray): Int

    /** Suspend (`paused = true`) or resume backgrounded media callbacks. */
    @JvmStatic
    external fun nativeSetPaused(handle: Long, paused: Boolean): Int

    /** Report thermal pressure on the normalized 0-3 scale. */
    @JvmStatic
    external fun nativeSetThermal(handle: Long, level: Int): Int

    @JvmStatic
    external fun nativeStop(handle: Long)
}
