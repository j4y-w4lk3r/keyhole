//! How a secret leaves the process.
//! A terminal uses the alternate screen, which is discarded. A pipe asked for the bytes.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

pub const ENTER_ALT: &[u8] = b"\x1b[?1049h\x1b[2J\x1b[H";
pub const LEAVE_ALT: &[u8] = b"\x1b[2J\x1b[?1049l";

static IN_ALT: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretSink {
    Terminal,
    Pipe,
}

pub fn secret_sink(stdout_is_tty: bool) -> SecretSink {
    if stdout_is_tty {
        SecretSink::Terminal
    } else {
        SecretSink::Pipe
    }
}

pub struct AltScreen;

impl AltScreen {
    pub fn enter() -> Result<Self, String> {
        install_restore_on_signal()?;
        write_stdout(ENTER_ALT)?;
        IN_ALT.store(true, Ordering::SeqCst);
        Ok(Self)
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        leave_once();
        restore_default_signals();
    }
}

pub fn reveal_on_terminal(username: &str, password: &str) -> Result<(), String> {
    let _screen = AltScreen::enter()?;
    let mut out = io::stdout();
    if !username.is_empty() {
        writeln!(out, "username: {username}").map_err(|e| e.to_string())?;
    }
    writeln!(out, "{password}").map_err(|e| e.to_string())?;
    writeln!(out, "\nPress Enter to hide.").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read enter: {e}"))?;
    Ok(())
}

fn write_stdout(bytes: &[u8]) -> Result<(), String> {
    let mut out = io::stdout();
    out.write_all(bytes).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn install_restore_on_signal() -> Result<(), String> {
    unsafe {
        let mut action = empty_action();
        action.sa_sigaction = restore_and_reraise as *const () as libc::sighandler_t;
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err("could not prepare the terminal restore handler".into());
        }
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
        {
            return Err("could not install the terminal restore handler".into());
        }
    }
    Ok(())
}

fn restore_default_signals() {
    unsafe {
        let action = empty_action();
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
    }
}

fn empty_action() -> libc::sigaction {
    unsafe {
        let mut action = std::mem::zeroed::<libc::sigaction>();
        action.sa_sigaction = libc::SIG_DFL;
        action
    }
}

fn leave_once() {
    if IN_ALT.swap(false, Ordering::SeqCst) {
        unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                LEAVE_ALT.as_ptr() as *const libc::c_void,
                LEAVE_ALT.len(),
            );
        }
    }
}

extern "C" fn restore_and_reraise(sig: i32) {
    leave_once();
    restore_default_signals();
    unsafe {
        libc::raise(sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_receives_the_secret_a_terminal_does_not_keep_it() {
        assert_eq!(secret_sink(false), SecretSink::Pipe);
        assert_eq!(secret_sink(true), SecretSink::Terminal);
    }
}
