//! Handing an access unit to the consumer without deadlocking on control.
//!
//! Shared by the Windows and macOS native pipelines. Deliberately *only* the
//! send-and-service lifecycle: capture and encode differ too much between the
//! two -- COM thread affinity and Desktop Duplication recovery on one side,
//! asynchronous VideoToolbox callbacks and two capture modes on the other --
//! for a generic worker to be an improvement. This is the part that was
//! genuinely identical, and the part that was identically wrong.
//!
//! # The deadlock this exists to prevent
//!
//! The worker thread produces access units into a bounded queue. The consumer
//! is the host's event loop, which also issues reconfiguration commands and
//! waits for the worker to acknowledge them. With a plain blocking send, a full
//! queue produces:
//!
//! ```text
//! worker: blocked sending    -- waiting for the consumer to take a unit
//! host:   reconfigure().await -- waiting for the worker to acknowledge
//! ```
//!
//! Neither can move. The host cannot drain the queue while it is awaiting, and
//! the worker cannot reach the control channel while it is parked on the send.
//! An eight-deep queue and one bitrate change were enough to reach it.
//!
//! # Why not answer without applying
//!
//! Replying to a reconfiguration before applying it would also break the cycle,
//! and would be worse: a command that had already timed out could be applied
//! afterwards, leaving the profile the host reports describing an encoder that
//! never received it. The acknowledgement has to keep meaning "this is in
//! force". So instead the worker services control *while* it waits for room.

use std::thread;
use std::time::Duration;

use tokio::sync::mpsc;

/// What happened to a unit offered to the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    /// The consumer has it.
    Sent,
    /// The worker should stop: the consumer is gone, or control said so.
    Stopped,
}

/// Longest gap between attempts once the queue has stayed full.
///
/// The wait starts at the caller's `retry` and doubles up to this. Ordinary
/// backpressure clears in a frame or two and never leaves the short end, so the
/// responsiveness that matters is unchanged; what this bounds is the other
/// case, a consumer that has stopped draining for seconds, where a fixed 1 ms
/// poll is a thousand wakeups a second to discover nothing has changed.
///
/// It also bounds how long a control message can sit unread, which is why it is
/// this small: a reconfiguration delayed by 10 ms is imperceptible, one delayed
/// by a second is a command the host has already given up on.
const MAX_RETRY: Duration = Duration::from_millis(10);

/// Hand `payload` to `units`, running `service_control` whenever the queue is
/// full.
///
/// `service_control` returns `false` to stop. It is called at least once per
/// retry while the queue is full, which is what lets a reconfiguration be
/// applied and acknowledged during the wait.
///
/// `retry` is the first gap between attempts; it doubles up to [`MAX_RETRY`]
/// while the queue stays full. A poll rather than a wait on a notification
/// because there is nothing to wait on: this runs on a plain thread, and
/// tokio's bounded sender offers no blocking "wait for capacity" that could be
/// woken by the control channel as well. Selecting over both would mean giving
/// the worker a runtime, which is a great deal of machinery for a wait that is
/// normally one frame long.
pub(crate) fn send_servicing_control<T>(
    payload: T,
    units: &mpsc::Sender<T>,
    retry: Duration,
    service_control: &mut dyn FnMut() -> bool,
) -> SendOutcome {
    let mut payload = payload;
    let mut wait = retry;
    loop {
        match units.try_send(payload) {
            Ok(()) => return SendOutcome::Sent,
            Err(mpsc::error::TrySendError::Closed(_)) => return SendOutcome::Stopped,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                payload = returned;
                if !service_control() {
                    return SendOutcome::Stopped;
                }
                thread::sleep(wait);
                wait = wait.saturating_mul(2).min(MAX_RETRY);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SendOutcome, send_servicing_control};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::mpsc;

    const RETRY: Duration = Duration::from_millis(1);

    /// The property that breaks the deadlock: control is serviced *while* the
    /// queue is full, not only between sends.
    ///
    /// This is the regression. A blocking send never reaches the control
    /// channel once it is parked, so the host's `reconfigure().await` and the
    /// worker's send wait for each other forever.
    #[test]
    fn control_is_serviced_while_the_queue_is_full() {
        let (tx, mut rx) = mpsc::channel::<u8>(1);
        tx.try_send(1).expect("fill the queue");

        let serviced = AtomicUsize::new(0);
        let mut service = || {
            // Stand in for the host finally taking a unit, but only after the
            // worker has had to ask about control at least once -- which is
            // exactly the ordering a blocking send cannot produce.
            if serviced.fetch_add(1, Ordering::Relaxed) == 0 {
                rx.try_recv().expect("drain one");
            }
            true
        };

        assert_eq!(
            send_servicing_control(2, &tx, RETRY, &mut service),
            SendOutcome::Sent
        );
        assert!(
            serviced.load(Ordering::Relaxed) >= 1,
            "control was never serviced during the wait, so a reconfigure \
             issued while the queue was full would never be answered"
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some(2),
            "the unit is delivered, not lost"
        );
    }

    /// A stop arriving during the wait ends the send rather than continuing to
    /// hold the payload.
    #[test]
    fn a_stop_during_the_wait_ends_the_send() {
        let (tx, _rx) = mpsc::channel::<u8>(1);
        tx.try_send(1).expect("fill the queue");

        let mut service = || false;
        assert_eq!(
            send_servicing_control(2, &tx, RETRY, &mut service),
            SendOutcome::Stopped
        );
    }

    /// A consumer that has gone away stops the worker, and does not spin.
    #[test]
    fn a_closed_consumer_stops_the_worker() {
        let (tx, rx) = mpsc::channel::<u8>(1);
        drop(rx);

        let serviced = AtomicUsize::new(0);
        let mut service = || {
            serviced.fetch_add(1, Ordering::Relaxed);
            true
        };
        assert_eq!(
            send_servicing_control(1, &tx, RETRY, &mut service),
            SendOutcome::Stopped
        );
        assert_eq!(
            serviced.load(Ordering::Relaxed),
            0,
            "a closed channel is recognised immediately, without a retry loop"
        );
    }

    /// The deadlock itself, with a real request and a real acknowledgement.
    ///
    /// The other tests prove the callback runs while the queue is full. This
    /// one models what the callback is *for*: a `Reconfigure` carrying a
    /// `oneshot` the host is blocked awaiting. The order is the whole point --
    /// the acknowledgement has to be sent before anything drains the unit
    /// queue, because in production nothing will drain it until the host
    /// receives that acknowledgement and returns from `reconfigure().await`.
    #[test]
    fn a_reconfigure_is_applied_and_acknowledged_while_the_queue_is_full() {
        let (tx, mut rx) = mpsc::channel::<u8>(1);
        tx.try_send(1).expect("fill the queue");

        // The host issues a bitrate change and waits for the reply.
        let (control_tx, control_rx) = std::sync::mpsc::channel();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<u32>();
        control_tx.send((48_000u32, reply_tx)).expect("issue");
        drop(control_tx);

        let applied = AtomicUsize::new(0);
        let mut service = || {
            while let Ok((bitrate, reply)) = control_rx.try_recv() {
                // Apply, *then* acknowledge: an acknowledgement that outran the
                // change would let the host report a profile the encoder never
                // received.
                applied.store(bitrate as usize, Ordering::Relaxed);
                let _ = reply.send(bitrate);
            }
            // Only once the host has its answer does it get back to draining.
            if applied.load(Ordering::Relaxed) != 0 {
                let _ = rx.try_recv();
            }
            true
        };

        assert_eq!(
            send_servicing_control(2, &tx, RETRY, &mut service),
            SendOutcome::Sent
        );
        assert_eq!(
            reply_rx.blocking_recv().ok(),
            Some(48_000),
            "the reconfiguration was never acknowledged, which is the half of \
             the deadlock the host is blocked on"
        );
        assert_eq!(applied.load(Ordering::Relaxed), 48_000);
        assert_eq!(rx.try_recv().ok(), Some(2), "the unit still arrives");
    }

    /// The wait grows, so a consumer that stops draining for a long time is not
    /// polled a thousand times a second.
    #[test]
    fn the_retry_interval_backs_off_and_is_capped() {
        let (tx, _rx) = mpsc::channel::<u8>(1);
        tx.try_send(1).expect("fill the queue");

        // Enough attempts to pass the cap several times over; the elapsed time
        // is what would run away without it.
        const ATTEMPTS: usize = 12;
        let serviced = AtomicUsize::new(0);
        let mut service = || serviced.fetch_add(1, Ordering::Relaxed) < ATTEMPTS - 1;

        let started = std::time::Instant::now();
        assert_eq!(
            send_servicing_control(2, &tx, RETRY, &mut service),
            SendOutcome::Stopped
        );
        let elapsed = started.elapsed();

        // Doubling from 1 ms capped at 10 ms: 1+2+4+8+10*7 = 85 ms. Ungrown it
        // would be 11 ms, so the growth is unmistakable; uncapped it would be
        // 2^11 ms, which is two seconds and is what the cap exists to stop.
        assert!(
            elapsed >= Duration::from_millis(40),
            "the interval did not grow: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "the interval grew past the cap: {elapsed:?}"
        );
    }

    /// Room straight away means no control round trip and no sleep.
    #[test]
    fn an_empty_queue_sends_without_servicing() {
        let (tx, mut rx) = mpsc::channel::<u8>(2);
        let serviced = AtomicUsize::new(0);
        let mut service = || {
            serviced.fetch_add(1, Ordering::Relaxed);
            true
        };
        assert_eq!(
            send_servicing_control(7, &tx, RETRY, &mut service),
            SendOutcome::Sent
        );
        assert_eq!(serviced.load(Ordering::Relaxed), 0);
        assert_eq!(rx.try_recv().ok(), Some(7));
    }
}
