import CoreMedia
import AVFoundation
import UIKit
import VideoToolbox

/// UIKit presentation for the H.264 Annex-B access units emitted by the
/// client-only Rust bridge. It drops access units while the display queue is
/// not ready instead of growing latency.
public final class OpenStreamVideoView: UIView {
    private struct PendingSample {
        let accessUnit: Data
        let presentationTimeUs: UInt64
    }

    private let displayLayer = AVSampleBufferDisplayLayer()
    private let pendingLock = NSLock()
    private var pending: [PendingSample] = []
    private var drainScheduled = false
    private let maxPendingSamples = 2
    private var formatDescription: CMVideoFormatDescription?
    private var sps: Data?
    private var pps: Data?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        displayLayer.videoGravity = .resizeAspect
        layer.addSublayer(displayLayer)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("OpenStreamVideoView is programmatic")
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        displayLayer.frame = bounds
    }

    /// Enqueue one Annex-B access unit. The callback may arrive off the main
    /// thread; the display layer is always touched on the main queue. The
    /// pending queue is bounded so a slow renderer cannot turn callback
    /// dispatch into unbounded latency.
    public func enqueue(_ accessUnit: Data, presentationTimeUs: UInt64) {
        pendingLock.lock()
        if pending.count >= maxPendingSamples {
            pending.removeFirst()
        }
        pending.append(PendingSample(
            accessUnit: accessUnit,
            presentationTimeUs: presentationTimeUs,
        ))
        let schedule = !drainScheduled
        if schedule {
            drainScheduled = true
        }
        pendingLock.unlock()
        if schedule {
            DispatchQueue.main.async { [weak self] in
                self?.drainNext()
            }
        }
    }

    private func drainNext() {
        pendingLock.lock()
        guard !pending.isEmpty else {
            drainScheduled = false
            pendingLock.unlock()
            return
        }
        let sample = pending.removeFirst()
        let continueDraining = !pending.isEmpty
        if !continueDraining {
            drainScheduled = false
        }
        pendingLock.unlock()

        enqueueOnMain(sample.accessUnit, presentationTimeUs: sample.presentationTimeUs)
        if continueDraining {
            DispatchQueue.main.async { [weak self] in
                self?.drainNext()
            }
        }
    }

    private func enqueueOnMain(_ accessUnit: Data, presentationTimeUs: UInt64) {
        let nalUnits = Self.nalUnits(in: accessUnit)
        var parameterSetsChanged = false
        for nal in nalUnits {
            guard let first = nal.first else { continue }
            switch first & 0x1f {
            case 7:
                parameterSetsChanged = parameterSetsChanged || sps != nal
                sps = nal
            case 8:
                parameterSetsChanged = parameterSetsChanged || pps != nal
                pps = nal
            default: break
            }
        }
        if parameterSetsChanged {
            formatDescription = nil
            displayLayer.flush()
        }
        guard let sps, let pps, !nalUnits.isEmpty else { return }
        if formatDescription == nil {
            formatDescription = Self.makeFormatDescription(sps: sps, pps: pps)
        }
        guard let formatDescription, displayLayer.isReadyForMoreMediaData else { return }

        var avcc = Data()
        for nal in nalUnits {
            var length = UInt32(nal.count).bigEndian
            withUnsafeBytes(of: &length) { avcc.append(contentsOf: $0) }
            avcc.append(nal)
        }

        var blockBuffer: CMBlockBuffer?
        let blockStatus = CMBlockBufferCreateEmpty(
            allocator: kCFAllocatorDefault,
            capacity: 1,
            flags: 0,
            blockBufferOut: &blockBuffer,
        )
        guard blockStatus == noErr, let blockBuffer else { return }
        let appendStatus = CMBlockBufferAppendMemoryBlock(
            blockBuffer,
            memoryBlock: nil,
            length: avcc.count,
            blockAllocator: kCFAllocatorDefault,
            customBlockSource: nil,
            offsetToData: 0,
            dataLength: avcc.count,
            flags: 0,
        )
        guard appendStatus == noErr else { return }
        let copyStatus = avcc.withUnsafeBytes { bytes in
            CMBlockBufferReplaceDataBytes(
                with: bytes.baseAddress,
                blockBuffer: blockBuffer,
                offsetIntoDestination: 0,
                dataLength: avcc.count,
            )
        }
        guard copyStatus == noErr else { return }

        var timing = CMSampleTimingInfo(
            duration: .invalid,
            presentationTimeStamp: CMTime(
                value: CMTimeValue(Int64(min(presentationTimeUs, UInt64(Int64.max)))),
                timescale: 1_000_000,
            ),
            decodeTimeStamp: .invalid,
        )
        var sampleSize = avcc.count
        var sampleBuffer: CMSampleBuffer?
        let sampleStatus = CMSampleBufferCreateReady(
            allocator: kCFAllocatorDefault,
            dataBuffer: blockBuffer,
            formatDescription: formatDescription,
            sampleCount: 1,
            sampleTimingEntryCount: 1,
            sampleTimingArray: &timing,
            sampleSizeEntryCount: 1,
            sampleSizeArray: &sampleSize,
            sampleBufferOut: &sampleBuffer,
        )
        guard sampleStatus == noErr, let sampleBuffer else { return }
        displayLayer.enqueue(sampleBuffer)
    }

    private static func makeFormatDescription(
        sps: Data,
        pps: Data,
    ) -> CMVideoFormatDescription? {
        var formatDescription: CMVideoFormatDescription?
        let status = sps.withUnsafeBytes { spsBytes in
            pps.withUnsafeBytes { ppsBytes in
                var pointers = [
                    spsBytes.bindMemory(to: UInt8.self).baseAddress!,
                    ppsBytes.bindMemory(to: UInt8.self).baseAddress!,
                ]
                var sizes = [sps.count, pps.count]
                return pointers.withUnsafeMutableBufferPointer { pointerBuffer in
                    sizes.withUnsafeMutableBufferPointer { sizeBuffer in
                        CMVideoFormatDescriptionCreateFromH264ParameterSets(
                            allocator: kCFAllocatorDefault,
                            parameterSetCount: 2,
                            parameterSetPointers: pointerBuffer.baseAddress!,
                            parameterSetSizes: sizeBuffer.baseAddress!,
                            nalUnitHeaderLength: 4,
                            formatDescriptionOut: &formatDescription,
                        )
                    }
                }
            }
        }
        return status == noErr ? formatDescription : nil
    }

    private static func nalUnits(in data: Data) -> [Data] {
        let bytes = [UInt8](data)
        var starts: [(offset: Int, length: Int)] = []
        var index = 0
        while index + 3 < bytes.count {
            if bytes[index] == 0, bytes[index + 1] == 0, bytes[index + 2] == 1 {
                starts.append((index, 3))
                index += 3
            } else if index + 4 < bytes.count,
                      bytes[index] == 0,
                      bytes[index + 1] == 0,
                      bytes[index + 2] == 0,
                      bytes[index + 3] == 1 {
                starts.append((index, 4))
                index += 4
            } else {
                index += 1
            }
        }
        return starts.enumerated().compactMap { position, start in
            let begin = start.offset + start.length
            let end = position + 1 < starts.count ? starts[position + 1].offset : bytes.count
            guard begin < end else { return nil }
            return Data(bytes[begin..<end])
        }
    }
}
