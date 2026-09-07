import UIKit

/// Minimal client-only iOS screen: H.264/PCM presentation plus touch input.
/// Production applications can replace this controller while retaining the
/// same OpenStreamSession and `OI` event boundary.
public final class OpenStreamViewController: UIViewController {
    private let signalOrigin: String
    private let pairingJSON: String
    private let videoView = OpenStreamVideoView()
    private let audioSink = OpenStreamAudioSink()
    private let haptic = UIImpactFeedbackGenerator(style: .heavy)
    private var session: OpenStreamSession?
    private var gamepadButtons: [UIButton] = []

    public init(signalOrigin: String, pairingJSON: String) {
        self.signalOrigin = signalOrigin
        self.pairingJSON = pairingJSON
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("OpenStreamViewController is programmatic")
    }

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        videoView.frame = view.bounds
        videoView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(videoView)
        addVirtualGamepad()
        session = OpenStreamSession(
            origin: signalOrigin,
            pairingJSON: pairingJSON,
            callbacks: .init(
                ready: { _, _, _ in },
                video: { [weak videoView] bytes, _, timestamp in
                    videoView?.enqueue(bytes, presentationTimeUs: timestamp)
                },
                audio: { [weak audioSink] pcm, _ in
                    audioSink?.enqueue(pcm)
                },
                rumble: { [weak haptic] _, strong, weak in
                    let strength = min(
                        1.0,
                        max(Float(strong) / 255.0, Float(weak) / 255.0),
                    )
                    DispatchQueue.main.async {
                        haptic?.impactOccurred(intensity: CGFloat(strength))
                    }
                },
                error: { code in
                    NSLog("OpenStream transport error: %d", code)
                },
            ),
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(thermalStateChanged),
            name: ProcessInfo.thermalStateDidChangeNotification,
            object: nil
        )
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func thermalStateChanged() {
        reportThermalState()
    }

    public override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        let size: CGFloat = 52
        let gap: CGFloat = 8
        let right = view.bounds.maxX - 16
        let bottom = view.bounds.maxY - 32
        for (index, button) in gamepadButtons.enumerated() {
            let column = CGFloat(index % 2)
            let row = CGFloat(index / 2)
            button.frame = CGRect(
                x: right - (2 - column) * size - (1 - column) * gap,
                y: bottom - (2 - row) * size - (1 - row) * gap,
                width: size,
                height: size
            )
        }
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Foreground return resumes media callbacks; the session itself
        // survived in the background with ACKs flowing.
        session?.setPaused(false)
        reportThermalState()
    }

    public override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Backgrounding suspends decoder/audio callbacks and input while the
        // Rust worker keeps the session alive for a fast return.
        session?.setPaused(true)
    }

    /// Map `ProcessInfo.thermalState` onto the bridge 0-3 scale so the
    /// worker sheds decode load before the OS intervenes.
    private func reportThermalState() {
        let level: UInt8 = switch ProcessInfo.processInfo.thermalState {
        case .nominal: 0
        case .fair: 1
        case .serious: 2
        case .critical: 3
        @unknown default: 3
        }
        session?.setThermalLevel(level)
    }

    private func addVirtualGamepad() {
        for (index, title) in ["X", "Y", "A", "B"].enumerated() {
            let button = UIButton(type: .system)
            button.setTitle(title, for: .normal)
            button.setTitleColor(.white, for: .normal)
            button.backgroundColor = UIColor(white: 0.15, alpha: 0.8)
            button.layer.cornerRadius = 26
            button.tag = index == 0 ? 2 : index == 1 ? 3 : index == 2 ? 0 : 1
            button.addTarget(self, action: #selector(gamepadDown(_:)), for: .touchDown)
            button.addTarget(self, action: #selector(gamepadUp(_:)), for: [.touchUpInside, .touchUpOutside, .touchCancel])
            view.addSubview(button)
            gamepadButtons.append(button)
        }
    }

    @objc private func gamepadDown(_ sender: UIButton) {
        sendInput(kind: 5, flags: 0, code: UInt32(sender.tag), value: 1, value2: 0)
    }

    @objc private func gamepadUp(_ sender: UIButton) {
        sendInput(kind: 5, flags: 0, code: UInt32(sender.tag), value: 0, value2: 0)
    }

    public override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesBegan(touches, with: event)
        sendPointerButton(pressed: true)
    }

    public override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesMoved(touches, with: event)
        guard let touch = touches.first else { return }
        let current = touch.location(in: view)
        let previous = touch.previousLocation(in: view)
        sendInput(kind: 2, flags: 1, code: 0, value: Int32(current.x - previous.x), value2: Int32(current.y - previous.y))
    }

    public override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesEnded(touches, with: event)
        sendPointerButton(pressed: false)
        sendInput(kind: 7, flags: 0, code: 0, value: 0, value2: 0)
    }

    public override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesCancelled(touches, with: event)
        sendPointerButton(pressed: false)
        sendInput(kind: 7, flags: 0, code: 0, value: 0, value2: 0)
    }

    private func sendPointerButton(pressed: Bool) {
        sendInput(kind: 3, flags: 0, code: 1, value: pressed ? 1 : 0, value2: 0)
    }

    private func sendInput(kind: UInt8, flags: UInt16, code: UInt32, value: Int32, value2: Int32) {
        var packet = Data([0x4f, 0x49, 1, kind])
        packet.append(UInt8(flags >> 8))
        packet.append(UInt8(flags & 0xff))
        appendBigEndian(UInt32(0), to: &packet)
        appendBigEndian(code, to: &packet)
        appendBigEndian(UInt32(bitPattern: value), to: &packet)
        appendBigEndian(UInt32(bitPattern: value2), to: &packet)
        let monotonic = DispatchTime.now().uptimeNanoseconds / 1_000
        appendBigEndian(monotonic, to: &packet)
        packet.append(contentsOf: [0, 0])
        _ = session?.sendInput(packet)
    }

    private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }
}
