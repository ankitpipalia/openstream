//! Fixture endpoint driven by the real IO shell.
//!
//! Same role and same command line as `punch peer`, and deliberately so: the
//! namespace fixtures judge both by the lines they print, so swapping one for
//! the other changes what is under test and nothing else.
//!
//! What differs is everything below the command line. `punch` calls the
//! connectivity engine directly through a hand-rolled loop with a blocking read
//! and a timer read per pass. This owns a `Shell`: the real socket with its full
//! option set, batched receive, batched send, the wake descriptor, and a wait
//! armed from the endpoint's own deadline. The topologies are the same, so what
//! this adds is the shell itself.
//!
//! The reflexive candidate is polled from the engine rather than read off a
//! return value. A shell processes datagrams in batches and has nowhere to put a
//! per-datagram result, which is exactly why the engine retains it.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("shell-punch is only available on Linux");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {

    use std::env;
    use std::fs;
    use std::io::{self, Write};
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use lowlat_common::clock::{Time, elapsed_ms};
    use lowlat_core::channel::{RecvRing, SlotMeta};
    use lowlat_core::conn::{Conn, Credentials, State};
    use lowlat_core::endpoint::{Endpoint, PathMtuRecovery};
    use lowlat_core::envelope::Envelope;
    use lowlat_core::pmtu::{PathConfig, PathMtuState};
    use lowlat_core::send::{SendRing, SendSlot};
    use lowlat_core::session::{Health, Session};
    use lowlat_net::{Shell, Socket, Wake};

    /// How long to keep running after a path is found.
    ///
    /// Answering checks outlives path selection, so an endpoint that exits the
    /// instant it establishes abandons the answer it owes the other side and
    /// strands a peer that was about to succeed. It would then report a one-sided
    /// result that says nothing about the topology.
    const SETTLE_MS: f64 = 600.0;

    /// Ring geometry. The ordinary topology fixture carries no application
    /// media, but keeping storage at the protocol ceiling lets the optional
    /// live-PMTU mode send a packet that becomes too large after the namespace
    /// link is lowered.
    const STORAGE_BODY: usize = lowlat_core::MAX_DATAGRAM
        - lowlat_core::envelope::ENVELOPE_LEN
        - lowlat_core::packet::HEADER_LEN;
    const ACTIVE_BODY: usize = lowlat_core::DEFAULT_DATAGRAM
        - lowlat_core::envelope::ENVELOPE_LEN
        - lowlat_core::packet::HEADER_LEN;
    const SLOTS: usize = 64;
    const CHANNEL: u8 = 1;
    const KEY: [u8; 32] = [0x77u8; 32];

    /// One frame-like application message. It fits in one datagram at a
    /// discovered 1472-byte IPv4 PLPMTU and becomes two fragments at BASE.
    const STREAM_PAYLOAD: usize = 1400;
    const STREAM_BURST: usize = 4;

    pub(super) fn run() {
        let args: Vec<String> = env::args().collect();
        if let Err(error) = peer(&args) {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }

    fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        let at = args.iter().position(|arg| arg == name)?;
        args.get(at + 1).map(String::as_str)
    }

    fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
        flag(args, name).ok_or_else(|| format!("missing {name}"))
    }

    /// Milestones are consumed by a supervising namespace fixture while this
    /// process is still running. Explicitly flush redirected stdout so the
    /// supervisor observes the state transition rather than waiting for a
    /// block-buffer to fill or the process to exit.
    fn flush_milestone() -> Result<(), String> {
        io::stdout()
            .flush()
            .map_err(|error| format!("flush milestone: {error}"))
    }

    fn watchdog_recovery_due(health: Health, already_recovered: bool) -> bool {
        health == Health::Undeliverable && !already_recovered
    }

    #[test]
    fn watchdog_recovery_requires_undeliverable_and_is_one_shot() {
        assert!(!watchdog_recovery_due(Health::Alive, false));
        assert!(!watchdog_recovery_due(Health::Stalled, false));
        assert!(watchdog_recovery_due(Health::Undeliverable, false));
        assert!(!watchdog_recovery_due(Health::Undeliverable, true));
    }

    fn peer(args: &[String]) -> Result<(), String> {
        // Only the port is taken from the bind address. Every fixture namespace
        // holds exactly one host address, and the socket is dual stack and bound to
        // the wildcard, so a v4 peer arrives v4-mapped -- which is the classification
        // the shell has to get right anyway.
        let bind: SocketAddr = required(args, "--bind")?
            .parse()
            .map_err(|_| "bad --bind".to_string())?;
        let publish = flag(args, "--publish").map(PathBuf::from);
        let expect = flag(args, "--await").map(PathBuf::from);
        let pmtu_ready = flag(args, "--pmtu-ready").map(PathBuf::from);
        let pmtu_recover = flag(args, "--pmtu-recover").map(PathBuf::from);
        let pmtu_raise = flag(args, "--pmtu-raise").map(PathBuf::from);
        let pmtu_ready_again = flag(args, "--pmtu-ready-again").map(PathBuf::from);
        let pmtu_watchdog = args.iter().any(|arg| arg == "--pmtu-watchdog");
        let stream = args.iter().any(|arg| arg == "--stream");
        let timeout_ms: f64 = required(args, "--timeout-ms")?
            .parse()
            .map_err(|_| "bad --timeout-ms".to_string())?;
        let verbose = args.iter().any(|a| a == "--verbose");
        let seed_byte: u8 = required(args, "--seed")?
            .parse()
            .map_err(|_| "bad --seed".to_string())?;

        let credentials = Credentials {
            local_ufrag: required(args, "--local-ufrag")?,
            local_pwd: required(args, "--local-pwd")?,
            remote_ufrag: required(args, "--remote-ufrag")?,
            remote_pwd: required(args, "--remote-pwd")?,
        };

        let mut recv_bodies = vec![0u8; STORAGE_BODY * SLOTS];
        let mut recv_meta = vec![SlotMeta::default(); SLOTS];
        let mut send_bodies = vec![0u8; STORAGE_BODY * SLOTS];
        let mut send_meta = vec![SendSlot::default(); SLOTS];

        let conn = Conn::new(credentials, [seed_byte; 16], 0.0);
        let envelope = Envelope::from_key(&KEY).map_err(|e| format!("key: {e}"))?;
        let mut session = match flag(args, "--session-role").unwrap_or("host") {
            "host" => Session::new(envelope, 1, 0.0),
            "guest" => Session::new_guest(envelope, 1, 0.0),
            _ => return Err("bad --session-role".to_string()),
        };
        session
            .attach_recv(
                CHANNEL,
                RecvRing::new(&mut recv_bodies, &mut recv_meta, STORAGE_BODY)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        session
            .attach_send(
                CHANNEL,
                SendRing::new_with_capacity(
                    &mut send_bodies,
                    &mut send_meta,
                    STORAGE_BODY,
                    ACTIVE_BODY,
                    CHANNEL,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;

        let socket = Socket::open(bind.port()).map_err(|e| format!("open {}: {e}", bind.port()))?;
        let wake = Wake::new().map_err(|e| format!("wake: {e}"))?;
        let mut shell = Shell::new(socket, wake, Endpoint::new(conn, session));

        for pair in args.windows(2) {
            let (name, value) = (&pair[0], &pair[1]);
            if name == "--server" {
                let server: SocketAddr = value.parse().map_err(|_| "bad --server".to_string())?;
                shell
                    .endpoint()
                    .conn()
                    .add_server(server)
                    .map_err(|e| e.to_string())?;
            }
        }

        // Signaling arrives on someone else's thread and is injected through the
        // wake, which is what an application does and what the wake descriptor is
        // for. Polling the rendezvous file from the loop instead would tie how fast
        // a candidate is noticed to how long the loop happens to be waiting, and
        // the loop waits on the endpoint's deadline -- tens of milliseconds when
        // nothing is due. That delay is invisible against a peer that waits, and
        // decisive against one that does not.
        let (candidates, inbox) = mpsc::channel::<SocketAddr>();
        if let Some(path) = expect.clone() {
            let notify = shell.wake_handle().map_err(|e| format!("handle: {e}"))?;
            thread::spawn(move || {
                loop {
                    if let Ok(text) = fs::read_to_string(&path)
                        && let Ok(addr) = text.trim().parse::<SocketAddr>()
                    {
                        if candidates.send(addr).is_err() {
                            return;
                        }
                        let _ = notify.notify();
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            });
        }

        if let Some(candidate) = flag(args, "--candidate") {
            let candidate: SocketAddr = candidate
                .parse()
                .map_err(|_| "bad --candidate".to_string())?;
            shell
                .endpoint()
                .conn()
                .add_candidate(candidate)
                .map_err(|e| e.to_string())?;
            println!("candidate {candidate}");
        }

        let started = Time::now();
        let mut published = false;
        let mut settled_at: Option<f64> = None;
        let mut stream_sequence = 0u64;
        let mut stream_sent = 0u64;
        let mut stream_sent_after_recovery = 0u64;
        let mut stream_received = 0u64;
        let mut stream_received_after_recovery = 0u64;
        let mut pmtu_round = 0u8;
        let mut pmtu_recovered_at = None;
        let mut watchdog_recovered = false;
        let mut pmtu_raise_requested = false;
        let mut pmtu_ready_again_written = false;
        let mut transition_complete_at = None;

        loop {
            let now_ms = elapsed_ms(started);
            if now_ms > timeout_ms {
                if stream {
                    println!(
                        "stream sent={stream_sent} sent_after_recovery={stream_sent_after_recovery} \
                         received={stream_received} after_recovery={stream_received_after_recovery}"
                    );
                }
                println!("timeout");
                return Ok(());
            }
            let settle_from = if pmtu_recover.is_some() || pmtu_watchdog || pmtu_raise.is_some() {
                transition_complete_at
            } else {
                settled_at
            };
            if let Some(at) = settle_from
                && now_ms > at + SETTLE_MS
            {
                if stream {
                    println!(
                        "stream sent={stream_sent} sent_after_recovery={stream_sent_after_recovery} \
                         received={stream_received} after_recovery={stream_received_after_recovery}"
                    );
                }
                return Ok(());
            }

            // Whatever signaling delivered, injected where the application's work is
            // pulled: after the wake has been taken, so nothing enqueued from here
            // on is lost.
            let mut arrived = None;
            let turn = shell
                .turn(now_ms, |endpoint| {
                    while let Ok(addr) = inbox.try_recv() {
                        if endpoint.conn().add_candidate(addr).is_ok() {
                            arrived = Some(addr);
                        }
                    }
                    if stream && settled_at.is_some() {
                        let mut payload = [0u8; STREAM_PAYLOAD];
                        for _ in 0..STREAM_BURST {
                            payload[..8].copy_from_slice(&stream_sequence.to_be_bytes());
                            if endpoint
                                .session()
                                .send_message(CHANNEL, b"MTU!", &payload)
                                .is_err()
                            {
                                break;
                            }
                            stream_sequence = stream_sequence.wrapping_add(1);
                            stream_sent = stream_sent.saturating_add(1);
                            if pmtu_recovered_at.is_some() {
                                stream_sent_after_recovery =
                                    stream_sent_after_recovery.saturating_add(1);
                            }
                        }
                    }
                })
                .map_err(|e| format!("turn: {e}"))?;
            if let Some(addr) = arrived {
                println!("candidate {addr}");
            }
            if verbose && (turn.received > 0 || turn.sent > 0) {
                println!(
                    "  {now_ms:.0} {:?} rx={} tx={}",
                    turn.woke, turn.received, turn.sent
                );
            }

            if pmtu_watchdog
                && watchdog_recovery_due(shell.endpoint().health(now_ms), watchdog_recovered)
            {
                match shell.recover_path_black_hole(now_ms) {
                    PathMtuRecovery::Recovered {
                        previous_datagram_size,
                        datagram_size,
                        dropped_video_fragments,
                    } => {
                        watchdog_recovered = true;
                        println!(
                            "pmtu-watchdog-recovered old={} new={} dropped={}",
                            previous_datagram_size, datagram_size, dropped_video_fragments
                        );
                        flush_milestone()?;
                        pmtu_recovered_at = Some(now_ms);
                        if pmtu_raise.is_none() {
                            transition_complete_at = Some(now_ms);
                        }
                    }
                    PathMtuRecovery::Blocked => {
                        return Err("pmtu recovery blocked by queued reliable data".to_string());
                    }
                    PathMtuRecovery::NotConfigured | PathMtuRecovery::Unusable => {
                        return Err("pmtu recovery found no usable configured path".to_string());
                    }
                }
            }

            if stream {
                let mut inbound = [0u8; STORAGE_BODY * 2];
                loop {
                    match shell
                        .endpoint()
                        .session()
                        .take_message(CHANNEL, &mut inbound)
                    {
                        Some(Ok(_)) => {
                            stream_received = stream_received.saturating_add(1);
                            if pmtu_recovered_at.is_some() {
                                stream_received_after_recovery =
                                    stream_received_after_recovery.saturating_add(1);
                            }
                        }
                        Some(Err(_)) => break,
                        None => break,
                    }
                }
                // A PMTU downgrade deliberately abandons old video sequence
                // numbers. Resume at the furthest complete frame-like message
                // rather than leaving the receiver permanently behind the gap.
                if shell.endpoint().session().has_gap(CHANNEL) {
                    let _ = shell.endpoint().session().escape_stall(CHANNEL, |body| {
                        body.get(4..8).is_some_and(|header| header == b"MTU!")
                    });
                }
            }

            if !published && let Some(mapped) = shell.endpoint().conn().reflexive().next() {
                if let Some(path) = publish.as_ref() {
                    fs::write(path, mapped.to_string()).map_err(|e| format!("publish: {e}"))?;
                }
                published = true;
                println!("reflexive {mapped}");
            }

            match shell.endpoint().conn().state() {
                State::Established(addr) => {
                    if settled_at.is_none() {
                        println!("established {addr}");
                        settled_at = Some(now_ms);
                    }
                }
                State::Failed(failure) => {
                    if stream {
                        println!(
                            "stream sent={stream_sent} sent_after_recovery={stream_sent_after_recovery} \
                             received={stream_received} after_recovery={stream_received_after_recovery}"
                        );
                    }
                    println!("failed {failure:?}");
                    return Ok(());
                }
                _ => {}
            }

            let complete = shell
                .path_mtu()
                .is_some_and(|mtu| mtu.state() == PathMtuState::SearchComplete);
            if complete && pmtu_round == 0 {
                if let Some(path) = pmtu_ready.as_ref() {
                    fs::write(path, "ready").map_err(|e| format!("pmtu ready: {e}"))?;
                }
                pmtu_round = 1;
                println!(
                    "pmtu-ready datagram={}",
                    shell.path_mtu().map_or(0, |mtu| mtu.datagram_size())
                );
                flush_milestone()?;
            } else if complete && pmtu_raise_requested && !pmtu_ready_again_written {
                if let Some(path) = pmtu_ready_again.as_ref() {
                    fs::write(path, "ready-again").map_err(|e| format!("pmtu ready again: {e}"))?;
                }
                pmtu_ready_again_written = true;
                pmtu_round = pmtu_round.saturating_add(1);
                transition_complete_at = Some(now_ms);
                println!(
                    "pmtu-ready-again datagram={}",
                    shell.path_mtu().map_or(0, |mtu| mtu.datagram_size())
                );
                flush_milestone()?;
            }

            if !pmtu_watchdog
                && let Some(path) = pmtu_recover.as_ref()
                && pmtu_recovered_at.is_none()
                && path.exists()
            {
                match shell.recover_path_black_hole(now_ms) {
                    PathMtuRecovery::Recovered {
                        previous_datagram_size,
                        datagram_size,
                        dropped_video_fragments,
                    } => {
                        println!(
                            "pmtu-recovered old={} new={} dropped={}",
                            previous_datagram_size, datagram_size, dropped_video_fragments
                        );
                        flush_milestone()?;
                        pmtu_recovered_at = Some(now_ms);
                        if pmtu_raise.is_none() {
                            transition_complete_at = Some(now_ms);
                        }
                    }
                    PathMtuRecovery::Blocked => {
                        return Err("pmtu recovery blocked by queued reliable data".to_string());
                    }
                    PathMtuRecovery::NotConfigured | PathMtuRecovery::Unusable => {
                        return Err("pmtu recovery found no usable configured path".to_string());
                    }
                }
            }

            if let Some(path) = pmtu_raise.as_ref()
                && !pmtu_raise_requested
                && (pmtu_recover.is_none() || pmtu_recovered_at.is_some())
                && path.exists()
            {
                if !shell.configure_path_mtu(PathConfig::direct_v4(1500), now_ms) {
                    return Err("pmtu raise could not reset the direct path".to_string());
                }
                pmtu_raise_requested = true;
                pmtu_ready_again_written = false;
                println!("pmtu-raise-requested");
                flush_milestone()?;
            }
        }
    }
}
