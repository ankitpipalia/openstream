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

/// Test-only seam, run inside [`LatestFramePublisher::publish`] between the
/// advisory `closed` check and the acquisition of the slot lock.
///
/// That gap is the race: a few instructions wide, and no amount of concurrent
/// stressing reproduces it dependably -- a twenty-thousand-iteration loop
/// against the unfixed code never once stranded a frame. A test that cannot
/// fail against the bug is not a regression test, so the window is made
/// addressable instead of hoped for.
///
/// Compiled out entirely otherwise.
#[cfg(test)]
mod race_hook {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
    }

    /// Run `hook` at the seam until [`clear`] is called.
    pub(super) fn set(hook: Box<dyn Fn()>) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
    }

    pub(super) fn clear() {
        HOOK.with(|slot| *slot.borrow_mut() = None);
    }

    pub(super) fn run() {
        // Cloned out of the RefCell's borrow before calling, so a hook that
        // re-enters `publish` cannot panic on an outstanding borrow.
        let hook = HOOK.with(|slot| slot.borrow().is_some());
        if hook {
            HOOK.with(|slot| {
                let taken = slot.borrow_mut().take();
                if let Some(run) = taken {
                    run();
                    *slot.borrow_mut() = Some(run);
                }
            });
        }
    }
}

#[cfg(test)]
#[inline]
fn at_publish_race_window() {
    race_hook::run();
}

#[cfg(not(test))]
#[inline(always)]
fn at_publish_race_window() {}

/// The shared slot behind a [`LatestFramePublisher`] and [`LatestFrameReader`].
#[derive(Debug)]
struct Slot<T> {
    /// `Mutex` rather than a lock-free cell because the value is owned and
    /// may be large: swapping it needs a place to put the old one, and the
    /// critical section is a pointer move.
    value: Mutex<Option<T>>,
    /// Set when the reader goes away, so a producer that never blocks can
    /// still learn to stop.
    ///
    /// **Written and read under `value`'s lock**, and additionally read outside
    /// it as an advisory fast path. It cannot be authoritative on its own: a
    /// publisher that checks it and *then* takes the lock can be overtaken by a
    /// reader that closes and drains in between, and would insert into a slot
    /// nobody will ever read again.
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
        // Advisory only: it saves taking the lock once shutdown is settled. A
        // `false` here means nothing, because the reader may close between this
        // load and the lock below.
        if self.slot.closed.load(Ordering::Acquire) {
            return FrameOffer::Closed;
        }
        at_publish_race_window();
        let Ok(mut held) = self.slot.value.lock() else {
            // A poisoned lock means a consumer panicked while holding it.
            // There is no consumer to deliver to any more, so this is the
            // same situation as a closed channel and is reported as one
            // rather than propagating someone else's panic.
            self.slot.closed.store(true, Ordering::Release);
            return FrameOffer::Closed;
        };
        // Authoritative, and the reason the flag is touched twice. The reader
        // sets it while holding this same lock, so a close that raced the check
        // above is visible here and the frame is dropped instead of stored.
        //
        // Without this the publisher could pass the first check, wait on the
        // lock while the reader closed and drained, and then insert into a slot
        // with no reader: the frame -- megabytes, for a decoded picture --
        // would be held for the publisher's whole lifetime, and the publisher
        // would be told `Enqueued` and go on producing for a consumer that no
        // longer exists.
        if self.slot.closed.load(Ordering::Acquire) {
            return FrameOffer::Closed;
        }
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
        // Close and drain under one lock, so the flag and the slot always
        // change together.
        //
        // This is defensive rather than load-bearing: the fix for the stranding
        // race is the re-check inside `publish`, and reverting this ordering
        // alone does not fail the regression test. It is kept because the
        // invariant "closed is only observed together with the slot" is what
        // makes that re-check correct, and a future second publisher path or a
        // rearrangement of `publish` would otherwise reopen the window silently.
        //
        // Releasing the held frame here, rather than leaving it for the
        // publisher's drop, is separate and does matter: a decoded frame is
        // megabytes and the publisher may outlive the window by the length of a
        // shutdown.
        match self.slot.value.lock() {
            Ok(mut held) => {
                self.slot.closed.store(true, Ordering::Release);
                held.take();
            }
            // Poisoned: the slot cannot be drained, but the producer must still
            // be told to stop.
            Err(_) => self.slot.closed.store(true, Ordering::Release),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::latest_frame;
    use crate::frame_age::FrameOffer;

    /// A frame must never be stranded in a slot whose reader has gone.
    ///
    /// The race: `publish` read `closed` and only then took the lock, while the
    /// reader's `Drop` stored `closed` *before* taking it. A publisher could
    /// pass the check, wait for the lock while the reader closed and drained,
    /// and then insert -- holding a decoded frame, which is megabytes, for the
    /// publisher's whole lifetime, and being told `Enqueued` so it carried on
    /// producing for a consumer that was gone.
    ///
    /// Driven through the test-only seam rather than by concurrent stress. The
    /// window is a few instructions wide; twenty thousand iterations of two
    /// threads racing never reproduced it once against the unfixed code, so a
    /// stress test here would have passed against the bug and been worse than
    /// no test at all.
    ///
    /// The publisher is deliberately alive at the assertion: a stranded frame
    /// is released when the last `Arc<Slot>` drops, so dropping the publisher
    /// first hides exactly what is being measured.
    #[test]
    fn a_frame_is_never_stranded_in_a_slot_whose_reader_has_gone() {
        use super::race_hook;
        use std::sync::{Arc, Mutex};

        let (publisher, reader) = latest_frame::<Arc<()>>();
        // Parked so the seam can drop it at the one moment that matters.
        let parked = Arc::new(Mutex::new(Some(reader)));
        {
            let parked = Arc::clone(&parked);
            race_hook::set(Box::new(move || {
                // Closes and drains, exactly as a window teardown would, in the
                // gap between the publisher's check and its lock.
                drop(parked.lock().expect("parked reader").take());
            }));
        }

        let canary = Arc::new(());
        let offer = publisher.publish(Arc::clone(&canary));
        race_hook::clear();

        assert_eq!(
            offer,
            FrameOffer::Closed,
            "a publisher that lost the race must be told the mailbox closed, \
             not that its frame was enqueued"
        );
        assert_eq!(
            Arc::strong_count(&canary),
            1,
            "the frame was stranded in a slot with no reader, and would be held \
             for the publisher's lifetime"
        );
        assert!(publisher.is_closed());
    }

    /// Publishing after the reader has gone reports the closure and keeps
    /// nothing.
    #[test]
    fn publishing_to_a_closed_mailbox_reports_it_and_holds_no_frame() {
        use std::sync::Arc;

        let canary = Arc::new(());
        let (publisher, reader) = latest_frame();
        drop(reader);
        assert_eq!(publisher.publish(Arc::clone(&canary)), FrameOffer::Closed);
        assert!(publisher.is_closed());
        assert_eq!(
            Arc::strong_count(&canary),
            1,
            "a refused frame must be dropped, not stored"
        );
    }

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
