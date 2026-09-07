//! Opt-in text clipboard adapter for host/client front ends.
//!
//! The platform crate deliberately uses fixed executable names and pipes text
//! over stdin/stdout. It never interpolates clipboard data into a shell
//! command. Native GUI applications can replace this adapter with their
//! toolkit API while keeping the same size and UTF-8 policy.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Maximum clipboard text accepted by the OpenStream protocol.
pub const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_COMMAND_STDERR_BYTES: usize = 8 * 1024;

/// Platform clipboard failures.
#[derive(Debug)]
pub enum Error {
    TooLarge,
    Unsupported,
    Spawn(std::io::Error),
    Io(std::io::Error),
    CommandFailed(String),
    OutputTooLarge,
    Timeout,
    InvalidUtf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("clipboard text exceeds 64 KiB"),
            Self::Unsupported => f.write_str("no supported clipboard adapter is available"),
            Self::Spawn(error) => write!(f, "could not start clipboard adapter: {error}"),
            Self::Io(error) => write!(f, "clipboard adapter I/O failed: {error}"),
            Self::CommandFailed(error) => write!(f, "clipboard adapter command failed: {error}"),
            Self::OutputTooLarge => f.write_str("clipboard adapter output exceeded the bound"),
            Self::Timeout => f.write_str("clipboard adapter timed out"),
            Self::InvalidUtf8(error) => write!(f, "clipboard output is not UTF-8: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// Return whether a supported adapter can be started on this target.
pub fn available() -> bool {
    adapters().is_some_and(|(readers, writers)| {
        readers
            .iter()
            .any(|command| command_exists(command.0, command.1))
            && writers
                .iter()
                .any(|command| command_exists(command.0, command.1))
    })
}

/// Read the current text clipboard. Empty text is a valid clipboard value.
pub fn read_text() -> Result<String, Error> {
    let Some((readers, _writers)) = adapters() else {
        return Err(Error::Unsupported);
    };
    let mut last_error = None;
    for (program, args) in readers {
        match run(program, args, None) {
            Ok(output) => return String::from_utf8(output).map_err(Error::InvalidUtf8),
            Err(Error::Spawn(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(Error::Unsupported))
}

/// Replace the current text clipboard without invoking a shell.
pub fn write_text(text: &str) -> Result<(), Error> {
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(Error::TooLarge);
    }
    let Some((_readers, writers)) = adapters() else {
        return Err(Error::Unsupported);
    };
    let mut last_error = None;
    for (program, args) in writers {
        match run(program, args, Some(text.as_bytes())) {
            Ok(_) => return Ok(()),
            Err(Error::Spawn(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(Error::Unsupported))
}

/// Clear the clipboard through the same bounded text path.
pub fn clear() -> Result<(), Error> {
    write_text("")
}

type CommandSpec = (&'static str, &'static [&'static str]);

fn adapters() -> Option<(&'static [CommandSpec], &'static [CommandSpec])> {
    #[cfg(target_os = "macos")]
    {
        const READERS: &[CommandSpec] = &[("pbpaste", &[])];
        const WRITERS: &[CommandSpec] = &[("pbcopy", &[])];
        Some((READERS, WRITERS))
    }
    #[cfg(target_os = "windows")]
    {
        const READERS: &[CommandSpec] = &[(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Clipboard -Raw",
            ],
        )];
        const WRITERS: &[CommandSpec] = &[("clip.exe", &[])];
        Some((READERS, WRITERS))
    }
    #[cfg(target_os = "linux")]
    {
        const READERS: &[CommandSpec] = &[
            ("wl-paste", &["--no-newline"]),
            ("xclip", &["-selection", "clipboard", "-o"]),
            ("xsel", &["--clipboard", "--output"]),
        ];
        const WRITERS: &[CommandSpec] = &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard", "-i"]),
            ("xsel", &["--clipboard", "--input"]),
        ];
        Some((READERS, WRITERS))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

fn command_exists(program: &str, args: &[&str]) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + COMMAND_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return true,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn run(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(Error::Spawn)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "clipboard stdout was not piped",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "clipboard stderr was not piped",
        )));
    };
    let stdout_reader = std::thread::spawn(move || read_limited(stdout, MAX_CLIPBOARD_BYTES));
    let stderr_reader = std::thread::spawn(move || read_limited(stderr, MAX_COMMAND_STDERR_BYTES));
    let stdin_writer = input.map(|input| {
        let input = input.to_vec();
        let stdin = child.stdin.take();
        std::thread::spawn(move || {
            let Some(mut stdin) = stdin else {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "clipboard stdin was not piped",
                )));
            };
            stdin.write_all(&input).map_err(Error::Io)
        })
    });
    // Close stdin immediately for read commands. For write commands the
    // writer thread drops it after the bounded payload is written.
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(Error::Io)? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                if let Some(writer) = stdin_writer {
                    let _ = writer.join();
                }
                return Err(Error::Timeout);
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if let Some(writer) = stdin_writer {
        writer
            .join()
            .map_err(|_| Error::Io(std::io::Error::other("clipboard writer thread panicked")))??;
    }
    let output = stdout_reader
        .join()
        .map_err(|_| Error::Io(std::io::Error::other("clipboard reader thread panicked")))??;
    let stderr = stderr_reader.join().map_err(|_| {
        Error::Io(std::io::Error::other(
            "clipboard error reader thread panicked",
        ))
    })??;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(Error::CommandFailed(stderr.trim().to_string()));
    }
    Ok(output)
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(limit.min(4096));
    let mut buffer = [0_u8; 4096];
    loop {
        let length = reader.read(&mut buffer).map_err(Error::Io)?;
        if length == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(length) > limit {
            return Err(Error::OutputTooLarge);
        }
        output.extend_from_slice(&buffer[..length]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_text_before_starting_a_process() {
        assert!(matches!(
            write_text(&"x".repeat(MAX_CLIPBOARD_BYTES + 1)),
            Err(Error::TooLarge)
        ));
    }
}
