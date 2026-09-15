//! A capacity-one mailbox that always holds the newest frame.
//!
//! # Why not a queue
//!
//! A bounded queue full of frames is a buffer of pictures the viewer has not
//! seen yet, and for an interactive stream every one of them is a picture
//! that is already wrong. The remote desktop has moved on; the pointer is
//! somewhere else. Draining that queue in order shows the viewer a small
//! recording of the recent past before catching up, and the time spent doing
//! it is added to the latency of every frame behind it.
//!
//! `try_send` on a full queue makes this worse in a specific way: it drops
//! the frame being offered -- the newest one -- and keeps the stale backlog.
//! So under load the viewer is shown exactly the frames that matter least.
//!
//! This holds one frame. Publishing replaces whatever has not been taken yet,
//! so the consumer always gets the most recent picture and the producer never
//! blocks. A slow presenter costs frame *rate*, which is what it should cost,
//! rather than frame *age*.
//!
//! # Why the replacement is counted rather than silent
//!
//! A replacement is not a fault -- it is the mailbox doing its job -- but a
//! stream producing them constantly is saying the presenter cannot keep up
//! with the decoder. That is worth seeing, and it is invisible if replacing
//! is indistinguishable from enqueuing.

use crate::frame_age::FrameOffer;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The shared slot behind a [`LatestFramePublisher`] and [`LatestFrameReader`].
#[derive(Debug)]
struct Slot<T> {
    /// `Mutex` rather than a lock-free cell because the value is owned and
    /// may be large: swapping it needs a place to put the old one, and the
    /// critical section is a pointer move.
    value: Mutex<Option<T>>,
    /// Set when the reader goes away, so a producer that never blocks can
    /// still learn to stop.
    closed: AtomicBool,
}

/// The producing end.
#[derive(Debug)]
pub struct LatestFramePublisher<T> {
    slot: Arc<Slot<T>>,
}

impl<T> Clone for LatestFramePublisher<T> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

/// The consuming end. Dropping it tells the producer to stop.
#[derive(Debug)]
pub struct LatestFrameReader<T> {
    slot: Arc<Slot<T>>,
}

/// Create a connected publisher and reader.
#[must_use]
pub fn latest_frame<T>() -> (LatestFramePublisher<T>, LatestFrameReader<T>) {
    let slot = Arc::new(Slot {
        value: Mutex::new(None),
        closed: AtomicBool::new(false),
    });
    (
        LatestFramePublisher {
            slot: Arc::clone(&slot),
        },
        LatestFrameReader { slot },
    )
}

impl<T> LatestFramePublisher<T> {
    /// Offer a frame. Never blocks, never fails for fullness.
    ///
    /// Returns [`FrameOffer::ReplacedOlder`] when an undelivered frame was
    /// displaced, so the caller can count how far behind the consumer is.
    pub fn publish(&self, value: T) -> FrameOffer {
        if self.slot.closed.load(Ordering::Acquire) {
            return FrameOffer::Closed;
        }
        let Ok(mut held) = self.slot.value.lock() else {
            // A poisoned lock means a consumer panicked while holding it.
            // There is no consumer to deliver to any more, so this is the
            // same situation as a closed channel and is reported as one
            // rather than propagating someone else's panic.
            self.slot.closed.store(true, Ordering::Release);
            return FrameOffer::Closed;
        };
        if held.replace(value).is_some() {
            FrameOffer::ReplacedOlder
        } else {
            FrameOffer::Enqueued
        }
    }

    /// Whether the consumer has gone away.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.slot.closed.load(Ordering::Acquire)
    }
}

impl<T> LatestFrameReader<T> {
    /// Take the newest frame, if one has arrived since the last take.
    pub fn take(&self) -> Option<T> {
        self.slot.value.lock().ok().and_then(|mut held| held.take())
    }

    /// Whether a frame is waiting.
    #[must_use]
    pub fn has_frame(&self) -> bool {
        self.slot
            .value
            .lock()
            .is_ok_and(|held| held.as_ref().is_some())
    }
}

impl<T> Drop for LatestFrameReader<T> {
    fn drop(&mut self) {
        self.slot.closed.store(true, Ordering::Release);
        // Release the held frame now rather than waiting for the publisher
        // to be dropped too: a decoded frame is megabytes, and the publisher
        // may outlive the window by the length of a shutdown.
        if let Ok(mut held) = self.slot.value.lock() {
            held.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::latest_frame;
    use crate::frame_age::FrameOffer;

    /// The consumer sees the newest frame, not the oldest one queued.
    ///
    /// This is the whole difference from a bounded queue: under load a queue
    /// hands the viewer a recording of the recent past, oldest first, and
    /// adds its own length to the latency of everything behind it.
    #[test]
    fn the_reader_always_gets_the_most_recent_frame() {
        let (publisher, reader) = latest_frame();
        assert_eq!(publisher.publish(1), FrameOffer::Enqueued);
        assert_eq!(publisher.publish(2), FrameOffer::ReplacedOlder);
        assert_eq!(publisher.publish(3), FrameOffer::ReplacedOlder);
        assert_eq!(reader.take(), Some(3), "the stale frames are not shown");
        assert_eq!(reader.take(), None, "and taking twice yields nothing");
    }

    /// Publishing never fails for fullness.
    ///
    /// A producer that can be refused has to decide what to do with the
    /// frame, and the only sensible answer -- throw it away -- is the wrong
    /// one, because it is the newest.
    #[test]
    fn publishing_never_reports_the_slot_as_full() {
        let (publisher, reader) = latest_frame();
        for value in 0..1_000 {
            let offer = publisher.publish(value);
            assert!(offer.delivered(), "offer {value} was not delivered");
            assert_ne!(offer, FrameOffer::DroppedNewest);
        }
        assert_eq!(reader.take(), Some(999));
    }

    /// A replacement is delivery, not loss.
    #[test]
    fn replacing_counts_as_delivered() {
        let (publisher, _reader) = latest_frame::<u32>();
        publisher.publish(1);
        let offer = publisher.publish(2);
        assert_eq!(offer, FrameOffer::ReplacedOlder);
        assert!(
            offer.delivered(),
            "the frame being offered is the one that will be shown"
        );
        assert!(!offer.should_stop());
    }

    /// The producer learns the consumer is gone.
    #[test]
    fn a_dropped_reader_closes_the_slot() {
        let (publisher, reader) = latest_frame();
        assert!(!publisher.is_closed());
        publisher.publish(1);
        drop(reader);
        assert!(publisher.is_closed());
        let offer = publisher.publish(2);
        assert_eq!(offer, FrameOffer::Closed);
        assert!(offer.should_stop());
    }

    /// Dropping the reader releases the held frame immediately.
    ///
    /// A decoded frame is megabytes, and the publisher can outlive the window
    /// by the length of a shutdown.
    #[test]
    fn a_dropped_reader_releases_the_frame_it_was_holding() {
        use std::sync::Arc;
        let (publisher, reader) = latest_frame();
        let frame = Arc::new(vec![0_u8; 16]);
        publisher.publish(Arc::clone(&frame));
        assert_eq!(Arc::strong_count(&frame), 2);
        drop(reader);
        assert_eq!(
            Arc::strong_count(&frame),
            1,
            "the slot must not pin a frame after the window is gone"
        );
    }

    /// An empty slot reports as empty.
    #[test]
    fn an_empty_slot_has_nothing_to_take() {
        let (publisher, reader) = latest_frame::<u32>();
        assert!(!reader.has_frame());
        assert_eq!(reader.take(), None);
        publisher.publish(7);
        assert!(reader.has_frame());
        reader.take();
        assert!(!reader.has_frame());
    }

    /// Producer and consumer running concurrently agree on the newest value.
    #[test]
    fn a_concurrent_producer_and_consumer_never_go_backwards() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (publisher, reader) = latest_frame::<u64>();
        let stop = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer = std::thread::spawn(move || {
            for value in 0..50_000_u64 {
                publisher.publish(value);
            }
            writer_stop.store(true, Ordering::Release);
        });

        // Whatever the reader sees must never be older than what it last saw:
        // the slot holds the newest value, so a take can skip values but can
        // never go back.
        let mut last = 0;
        while !stop.load(Ordering::Acquire) {
            if let Some(value) = reader.take() {
                assert!(value >= last, "{value} came after {last}");
                last = value;
            }
        }
        writer.join().expect("writer thread");
    }
}
