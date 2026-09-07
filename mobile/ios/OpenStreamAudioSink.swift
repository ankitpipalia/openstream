import AVFoundation

/// Small AVAudioEngine sink for interleaved 48 kHz stereo signed-16-bit PCM.
public final class OpenStreamAudioSink {
    private let queueLock = NSLock()
    private var pending: [[Int16]] = []
    private var scheduledBuffers = 0
    private var drainScheduled = false
    private let maxPendingBuffers = 8
    private let maxScheduledBuffers = 2
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let format = AVAudioFormat(standardFormatWithSampleRate: 48_000, channels: 2)!

    public init() {
        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: format)
        try? engine.start()
        player.play()
    }

    deinit {
        player.stop()
        engine.stop()
    }

    public func enqueue(_ pcm: [Int16]) {
        guard pcm.count >= 2 else { return }
        queueLock.lock()
        if pending.count >= maxPendingBuffers {
            pending.removeFirst()
        }
        pending.append(pcm)
        let schedule = !drainScheduled
        if schedule {
            drainScheduled = true
        }
        queueLock.unlock()
        if schedule {
            DispatchQueue.main.async { [weak self] in
                self?.drainNext()
            }
        }
    }

    private func drainNext() {
        queueLock.lock()
        guard !pending.isEmpty else {
            drainScheduled = false
            // AVAudioPlayerNode keeps its own scheduled-buffer queue. Wait
            // for a completion callback before moving more pending PCM into
            // it, otherwise a slow audio device can accumulate seconds of
            // latency despite the bounded Swift array above.
            queueLock.unlock()
            return
        }
        guard scheduledBuffers < maxScheduledBuffers else {
            // No drain task is outstanding once this invocation reaches the
            // scheduling ceiling. Let the next completion callback schedule
            // another pass; leaving this set would strand the pending queue.
            drainScheduled = false
            queueLock.unlock()
            return
        }
        let samples = pending.removeFirst()
        scheduledBuffers += 1
        let continueDraining = !pending.isEmpty
        if !continueDraining {
            drainScheduled = false
        }
        queueLock.unlock()

        let frames = samples.count / 2
        guard frames > 0,
              let buffer = AVAudioPCMBuffer(
                  pcmFormat: format,
                  frameCapacity: AVAudioFrameCount(frames),
              ),
              let channels = buffer.floatChannelData else {
            completeScheduledBuffer()
            if continueDraining {
                scheduleDrain()
            }
            return
        }
        buffer.frameLength = AVAudioFrameCount(frames)
        for frame in 0..<frames {
            channels[0][frame] = Float(samples[frame * 2]) / 32_768.0
            channels[1][frame] = Float(samples[frame * 2 + 1]) / 32_768.0
        }
        player.scheduleBuffer(buffer) { [weak self] _ in
            self?.completeScheduledBuffer()
        }
        if continueDraining {
            scheduleDrain()
        }
    }

    private func completeScheduledBuffer() {
        queueLock.lock()
        scheduledBuffers = max(0, scheduledBuffers - 1)
        let schedule = !pending.isEmpty && !drainScheduled
        if schedule {
            drainScheduled = true
        }
        queueLock.unlock()
        if schedule {
            DispatchQueue.main.async { [weak self] in
                self?.drainNext()
            }
        }
    }

    private func scheduleDrain() {
        DispatchQueue.main.async { [weak self] in
            self?.drainNext()
        }
    }
}
