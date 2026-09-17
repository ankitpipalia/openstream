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

/// Hand `payload` to `units`, running `service_control` whenever the queue is
/// full.
///
/// `service_control` returns `false` to stop. It is called at least once per
/// retry while the queue is full, which is what lets a reconfiguration be
/// applied and acknowledged during the wait.
///
/// `retry` is how long to wait between attempts. It bounds how long a control
/// message can sit unread; a full queue only happens while the consumer is
/// behind, which is transient, so this is a poll rather than a hot spin.
pub(crate) fn send_servicing_control<T>(
    payload: T,
    units: &mpsc::Sender<T>,
    retry: Duration,
    service_control: &mut dyn FnMut() -> bool,
) -> SendOutcome {
    let mut payload = payload;
    loop {
        match units.try_send(payload) {
            Ok(()) => return SendOutcome::Sent,
            Err(mpsc::error::TrySendError::Closed(_)) => return SendOutcome::Stopped,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                payload = returned;
                if !service_control() {
                    return SendOutcome::Stopped;
                }
                thread::sleep(retry);
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
