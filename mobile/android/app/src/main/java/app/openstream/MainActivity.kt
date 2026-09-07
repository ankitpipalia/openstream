package app.openstream

import android.app.Activity
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

/** Client-only Android front end for the OpenStream Rust bridge. */
class MainActivity : Activity() {
    private data class VideoSample(
        val bytes: ByteArray,
        val presentationTimeUs: Long,
        val keyframe: Boolean,
    )

    private lateinit var surfaceView: SurfaceView
    private lateinit var origin: EditText
    private lateinit var pairing: EditText
    private lateinit var status: TextView

    private val decodeThread = HandlerThread("openstream-video").apply { start() }
    private val decodeHandler = Handler(decodeThread.looper)
    private val videoQueue = ArrayBlockingQueue<VideoSample>(2)
    private val videoPumpScheduled = AtomicBoolean(false)
    private val videoPump = object : Runnable {
        override fun run() {
            try {
                videoQueue.poll()?.let { sample ->
                    queueVideo(sample.bytes, sample.presentationTimeUs)
                }
            } finally {
                videoPumpScheduled.set(false)
                if (videoQueue.isNotEmpty()) scheduleVideoPump()
            }
        }
    }
    private val audioThread = HandlerThread("openstream-audio").apply { start() }
    private val audioHandler = Handler(audioThread.looper)
    private val audioQueue = ArrayBlockingQueue<ShortArray>(8)
    private val audioPumpScheduled = AtomicBoolean(false)
    private val audioPump = object : Runnable {
        override fun run() {
            try {
                audioQueue.poll()?.let { pcm -> playAudio(pcm) }
            } finally {
                audioPumpScheduled.set(false)
                if (audioQueue.isNotEmpty()) scheduleAudioPump()
            }
        }
    }
    @Volatile
    private var clientHandle = 0L
    private val clientLock = Any()
    private var thermalListener: Any? = null
    private var decoder: MediaCodec? = null
    private var videoWidth = 0
    private var videoHeight = 0
    private var audioTrack: AudioTrack? = null
    private var audioUnavailable = false
    private var lastX = 0f
    private var lastY = 0f

    private val vibrator: Vibrator by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            getSystemService(VibratorManager::class.java).defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(VIBRATOR_SERVICE) as Vibrator
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        surfaceView = SurfaceView(this)
        origin = EditText(this).apply {
            hint = "Signal origin, e.g. https://signal.example"
            setSingleLine(true)
            setText("http://10.0.2.2:8080")
        }
        pairing = EditText(this).apply {
            hint = "Pairing JSON"
            minLines = 3
        }
        status = TextView(this).apply { text = "Disconnected" }
        val connect = Button(this).apply {
            text = "Connect"
            setOnClickListener { startSession() }
        }
        val gamepad = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            listOf("A" to 0, "B" to 1, "X" to 2, "Y" to 3).forEach { (label, code) ->
                addView(Button(this@MainActivity).apply {
                    text = label
                    setOnTouchListener { _, event ->
                        when (event.actionMasked) {
                            MotionEvent.ACTION_DOWN -> sendGamepadButton(code, true)
                            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                                sendGamepadButton(code, false)
                        }
                        true
                    }
                }, LinearLayout.LayoutParams(0, -2, 1f))
            }
        }
        val controls = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            addView(origin)
            addView(pairing)
            addView(connect)
            addView(gamepad)
            addView(status)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(surfaceView, LinearLayout.LayoutParams(-1, 0, 1f))
            addView(controls, LinearLayout.LayoutParams(-1, -2))
        }
        setContentView(root)
        surfaceView.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) {
                decodeHandler.post { configureDecoderIfPossible() }
            }

            override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
                decodeHandler.post { configureDecoderIfPossible() }
            }

            override fun surfaceDestroyed(holder: SurfaceHolder) {
                decodeHandler.post {
                    decoder?.runCatching { stop() }
                    decoder?.release()
                    decoder = null
                }
            }
        })
        surfaceView.setOnTouchListener(::handleTouch)
        registerThermalListener()
    }

    private fun startSession() {
        stopSession()
        val callbacks = object : OpenStreamNative.Callbacks() {
            override fun onReady(width: Int, height: Int, fps: Int) {
                videoWidth = width
                videoHeight = height
                runOnUiThread {
                    status.text = "Connected: ${width}x${height} @ ${fps}fps"
                }
                decodeHandler.post { configureDecoderIfPossible() }
            }

            override fun onVideo(bytes: ByteArray, keyframe: Boolean, presentationTimeUs: Long) {
                // JNI has already copied the access unit. Drop an input access
                // unit when MediaCodec or this bounded queue is full to
                // preserve interactive latency. Retain a queued keyframe when
                // possible; dropping all interframes until the next keyframe
                // is preferable to building seconds of decoder backlog.
                val sample = VideoSample(bytes, presentationTimeUs, keyframe)
                if (!videoQueue.offer(sample)) {
                    val oldest = videoQueue.peek()
                    if (!keyframe && oldest?.keyframe == true) return
                    videoQueue.poll()
                    if (!videoQueue.offer(sample)) return
                }
                scheduleVideoPump()
            }

            override fun onAudio(pcm: ShortArray, presentationTimeUs: Long) {
                // Audio must never be written from the UI thread. Keep at
                // most 160 ms of PCM and discard the oldest fragment when a
                // slow device falls behind.
                if (!audioQueue.offer(pcm)) {
                    audioQueue.poll()
                    audioQueue.offer(pcm)
                }
                scheduleAudioPump()
            }

            override fun onRumble(deviceId: Int, strong: Byte, weak: Byte) {
                val amplitude = maxOf(strong.toInt() and 0xff, weak.toInt() and 0xff)
                if (amplitude == 0) return
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(
                        VibrationEffect.createOneShot(
                            120L,
                            amplitude.coerceIn(1, 255),
                        ),
                    )
                } else {
                    @Suppress("DEPRECATION")
                    vibrator.vibrate(120L)
                }
            }

            override fun onError(code: Int) {
                runOnUiThread { status.text = "Transport error: $code" }
            }
        }
        val handle = OpenStreamNative.nativeStart(
            origin.text.toString().trim(),
            pairing.text.toString(),
            callbacks,
        )
        synchronized(clientLock) {
            clientHandle = handle
        }
        if (handle == 0L) {
            status.text = "Could not start client"
        }
    }

    private fun configureDecoderIfPossible() {
        if (decoder != null || videoWidth <= 0 || videoHeight <= 0 || !surfaceView.holder.surface.isValid) {
            return
        }
        val format = MediaFormat.createVideoFormat("video/avc", videoWidth, videoHeight)
        var created: MediaCodec? = null
        runCatching {
            created = MediaCodec.createDecoderByType("video/avc")
            created!!.configure(format, surfaceView.holder.surface, null, 0)
            created!!.start()
        }.onSuccess {
            decoder = created
        }.onFailure { error ->
            created?.runCatching { release() }
            runOnUiThread {
                status.text = "Video decoder unavailable: ${error.message ?: "unknown error"}"
            }
        }
    }

    private fun queueVideo(bytes: ByteArray, presentationTimeUs: Long) {
        configureDecoderIfPossible()
        val codec = decoder ?: return
        try {
            val input = codec.dequeueInputBuffer(0)
            if (input < 0) return
            codec.getInputBuffer(input)?.let { buffer ->
                buffer.clear()
                // A transport fragment can be valid while an access unit is
                // too large for the decoder's current input slot. Refuse it
                // before `put` rather than allowing a BufferOverflowException
                // to tear down the decoder thread.
                if (bytes.size > buffer.remaining()) return
                buffer.put(bytes)
                codec.queueInputBuffer(input, 0, bytes.size, presentationTimeUs, 0)
            }
            val info = MediaCodec.BufferInfo()
            while (true) {
                val output = codec.dequeueOutputBuffer(info, 0)
                if (output < 0) break
                codec.releaseOutputBuffer(output, true)
            }
        } catch (error: RuntimeException) {
            // CodecException/IllegalStateException can occur after a driver
            // reset or surface loss. Keep the decode HandlerThread alive and
            // let the next session recreate a clean decoder.
            if (decoder === codec) {
                decoder = null
                codec.runCatching { release() }
            }
            runOnUiThread {
                status.text = "Video decoder stopped: ${error.message ?: "codec failure"}"
            }
        }
    }

    private fun scheduleVideoPump() {
        if (videoPumpScheduled.compareAndSet(false, true)) {
            decodeHandler.post(videoPump)
        }
    }

    private fun scheduleAudioPump() {
        if (audioPumpScheduled.compareAndSet(false, true)) {
            audioHandler.post(audioPump)
        }
    }

    private fun playAudio(pcm: ShortArray) {
        if (audioUnavailable) return
        if (audioTrack == null) {
            val minimum = AudioTrack.getMinBufferSize(
                48_000,
                AudioFormat.CHANNEL_OUT_STEREO,
                AudioFormat.ENCODING_PCM_16BIT,
            )
            audioTrack = runCatching {
                AudioTrack.Builder()
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_GAME)
                            .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                            .build(),
                    )
                    .setAudioFormat(
                        AudioFormat.Builder()
                            .setSampleRate(48_000)
                            .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .build(),
                    )
                    .setBufferSizeInBytes(minimum.coerceAtLeast(48_000))
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .build()
                    .also { it.play() }
            }.getOrElse { error ->
                audioUnavailable = true
                runOnUiThread {
                    status.text = "Audio output unavailable: ${error.message ?: "AudioTrack failure"}"
                }
                return
            }
        }
        val written = runCatching {
            audioTrack?.write(pcm, 0, pcm.size, AudioTrack.WRITE_BLOCKING) ?: -1
        }.getOrElse { error ->
            audioUnavailable = true
            audioTrack?.runCatching { release() }
            audioTrack = null
            runOnUiThread {
                status.text = "Audio output stopped: ${error.message ?: "AudioTrack failure"}"
            }
            return
        }
        if (written < 0) {
            audioUnavailable = true
            audioTrack?.runCatching { release() }
            audioTrack = null
            runOnUiThread { status.text = "Audio output stopped" }
        }
    }

    private fun handleTouch(view: View, event: MotionEvent): Boolean {
        if (clientHandle == 0L) return false
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                lastX = event.x
                lastY = event.y
                sendPointerButton(true)
            }
            MotionEvent.ACTION_MOVE -> {
                val dx = event.x - lastX
                val dy = event.y - lastY
                lastX = event.x
                lastY = event.y
                sendPointerMotion(dx.toInt(), dy.toInt())
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                sendPointerButton(false)
                sendRelease()
            }
        }
        return true
    }

    private fun sendPointerMotion(dx: Int, dy: Int) {
        sendInput(kind = 2, flags = 1, code = 0, value = dx, value2 = dy)
    }

    private fun sendPointerButton(pressed: Boolean) {
        sendInput(kind = 3, flags = 0, code = 1, value = if (pressed) 1 else 0, value2 = 0)
    }

    private fun sendGamepadButton(code: Int, pressed: Boolean) {
        sendInput(kind = 5, flags = 0, code = code, value = if (pressed) 1 else 0, value2 = 0)
    }

    private fun sendRelease() {
        sendInput(kind = 7, flags = 0, code = 0, value = 0, value2 = 0)
    }

    private fun sendInput(kind: Int, flags: Int, code: Int, value: Int, value2: Int) {
        val handle = synchronized(clientLock) { clientHandle }
        if (handle == 0L) return
        val bytes = ByteBuffer.allocate(32).order(ByteOrder.BIG_ENDIAN).apply {
            put(0x4f.toByte())
            put(0x49.toByte())
            put(1.toByte())
            put(kind.toByte())
            putShort(flags.toShort())
            putInt(0)
            putInt(code)
            putInt(value)
            putInt(value2)
            putLong(System.nanoTime() / 1_000L)
            putShort(0)
        }.array()
        synchronized(clientLock) {
            if (clientHandle == handle) {
                OpenStreamNative.nativeSendInput(handle, bytes)
            }
        }
    }

    private fun stopSession() {
        videoQueue.clear()
        audioQueue.clear()
        synchronized(clientLock) {
            val handle = clientHandle
            if (handle != 0L) {
                // Mark it dead before sending the release so thermal/input
                // callbacks cannot enter the native handle while it is being
                // joined and freed.
                clientHandle = 0L
                val bytes = ByteBuffer.allocate(32).order(ByteOrder.BIG_ENDIAN).apply {
                    put(0x4f.toByte())
                    put(0x49.toByte())
                    put(1.toByte())
                    put(7.toByte())
                    putShort(0)
                    putInt(0)
                    putInt(0)
                    putInt(0)
                    putInt(0)
                    putLong(System.nanoTime() / 1_000L)
                    putShort(0)
                }.array()
                OpenStreamNative.nativeSendInput(handle, bytes)
                OpenStreamNative.nativeStop(handle)
            }
        }
        decodeHandler.post {
            decoder?.runCatching { stop() }
            decoder?.release()
            decoder = null
        }
        audioHandler.post {
            audioTrack?.runCatching { stop() }
            audioTrack?.release()
            audioTrack = null
            audioUnavailable = false
        }
    }

    override fun onPause() {
        // Backgrounding suspends decoder/audio callbacks and input while the
        // Rust worker keeps the session (and its ACKs) alive for a fast
        // foreground return. See openstream_client_set_paused.
        if (clientHandle != 0L) {
            synchronized(clientLock) {
                if (clientHandle != 0L) {
                    OpenStreamNative.nativeSetPaused(clientHandle, true)
                }
            }
        }
        super.onPause()
    }

    override fun onResume() {
        super.onResume()
        if (clientHandle != 0L) {
            synchronized(clientLock) {
                if (clientHandle != 0L) {
                    OpenStreamNative.nativeSetPaused(clientHandle, false)
                }
            }
        }
    }

    override fun onDestroy() {
        unregisterThermalListener()
        stopSession()
        decodeThread.quitSafely()
        audioThread.quitSafely()
        super.onDestroy()
    }

    /**
     * Forward OS thermal pressure to the Rust worker so it sheds decode load
     * (predicted frames, then PCM) before the system kills the app. Levels
     * follow PowerManager thermal status mapped onto the normalized 0-3
     * scale; below API 29 there is no callback and the worker stays nominal.
     */
    private fun registerThermalListener() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        if (thermalListener != null) return
        val power = getSystemService(POWER_SERVICE) as android.os.PowerManager
        val listener = android.os.PowerManager.OnThermalStatusChangedListener { status ->
            val level = when {
                status >= android.os.PowerManager.THERMAL_STATUS_CRITICAL -> 3
                status >= android.os.PowerManager.THERMAL_STATUS_SEVERE -> 2
                status >= android.os.PowerManager.THERMAL_STATUS_MODERATE -> 1
                else -> 0
            }
            if (clientHandle != 0L) {
                synchronized(clientLock) {
                    if (clientHandle != 0L) {
                        OpenStreamNative.nativeSetThermal(clientHandle, level)
                    }
                }
            }
        }
        power.addThermalStatusListener(decodeHandler.looper.executor, listener)
        thermalListener = listener
    }

    private fun unregisterThermalListener() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val listener =
            thermalListener as? android.os.PowerManager.OnThermalStatusChangedListener ?: return
        val power = getSystemService(POWER_SERVICE) as android.os.PowerManager
        power.removeThermalStatusListener(listener)
        thermalListener = null
    }
}
