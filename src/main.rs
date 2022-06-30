// SPDX-License-Identifier: GPL-3.0-only

use smithay::reexports::{
    calloop::{generic::Generic, EventLoop, Interest, Mode, PostAction},
    wayland_server::Display,
};

use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use sendfd::RecvWithFd;
use std::{
    ffi::OsString,
    os::unix::{
        io::{FromRawFd, AsRawFd, RawFd},
        net::UnixStream,
    },
    sync::atomic::Ordering,
};

pub mod backend;
pub mod config;
pub mod input;
mod logger;
pub mod shell;
pub mod state;
pub mod systemd;
pub mod utils;
pub mod wayland;

#[cfg(feature = "debug")]
pub mod debug;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum Message {
	SetEnv { variables: std::collections::HashMap<String, String> },
	NewPrivilegedClient { count: usize },
}

struct StreamWrapper {
    reader: std::io::BufReader<UnixStream>,
}
impl AsRawFd for StreamWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.reader.get_ref().as_raw_fd()
    }
}
impl From<UnixStream> for StreamWrapper {
    fn from(stream: UnixStream) -> StreamWrapper {
        StreamWrapper {
            reader: std::io::BufReader::new(stream),
        }
    }
}

fn main() -> Result<()> {
    // setup logger
    let log = logger::init_logger()?;
    slog_scope::info!("Cosmic starting up!");

    // init event loop
    let mut event_loop =
        EventLoop::try_new_high_precision().with_context(|| "Failed to initialize event loop")?;
    // init wayland
    let (display, socket) = init_wayland_display(&mut event_loop)?;
    // init state
    let mut state = state::State::new(
        display,
        socket,
        event_loop.handle(),
        event_loop.get_signal(),
        log,
    );
    // init backend
    backend::init_backend_auto(&mut event_loop, &mut state)?;
    // potentially tell systemd we are setup now
    systemd::ready(&state);

    if let Ok(fd_num) = std::env::var("COSMIC_SESSION_SOCK") {
        if let Ok(fd) = fd_num.parse::<RawFd>() {
            let session_socket = unsafe { UnixStream::from_raw_fd(fd) };
            event_loop.handle().insert_source(
                Generic::new(StreamWrapper::from(session_socket), Interest::READ, Mode::Level),
                move |_, stream, state: &mut state::State| {
                    use std::io::BufRead;

                    let mut line = String::new();
                    match stream.reader.read_line(&mut line) {
                        Ok(x) if x > 0 => {
                            match serde_json::from_str::<'_, Message>(&line) {
                                Ok(Message::NewPrivilegedClient { count }) => {
                                    let mut buffer = [0; 1];
                                    let mut fds = vec![0; count];
                                    match stream.reader.get_mut().recv_with_fd(&mut buffer, &mut *fds) {
                                        Ok((_, received_count)) => {
                                            assert_eq!(received_count, count);
                                            for fd in fds.into_iter().take(received_count) {
                                                let display = state.common.display.clone();
                                                unsafe { display.borrow_mut().create_client(fd, state) };
                                            }
                                        },
                                        Err(err) => {
                                            slog_scope::warn!("Failed to read file descriptors from session sock: {}", err);
                                        }
                                    }
                                },
                                Ok(Message::SetEnv { .. }) => slog_scope::warn!("Got SetEnv from session? What is this?"),
                                _ => slog_scope::warn!("Unknown session socket message, are you using incompatible cosmic-session and cosmic-comp versions?"),
                            };
                            Ok(PostAction::Continue)
                        },
                        Ok(_) => Ok(PostAction::Disable),
                        Err(err) => {
                            slog_scope::warn!("Error reading from session socket: {}", err);
                            Ok(PostAction::Remove)
                        },
                    }
                },
            ).with_context(|| "Failed to init the cosmic session socket source")?;
        }
        slog_scope::error!("COSMIC_SESSION_SOCK is no valid RawFd: {}", fd_num);
    };

    // run the event loop
    event_loop.run(None, &mut state, |state| {
        // shall we shut down?
        if state.common.shell.outputs().next().is_none() || state.common.should_stop {
            slog_scope::info!("Shutting down");
            state.common.event_loop_signal.stop();
            state.common.event_loop_signal.wakeup();
            return;
        }

        // do we need to trigger another render
        if state.common.dirty_flag.swap(false, Ordering::SeqCst) {
            for output in state.common.shell.outputs() {
                state
                    .backend
                    .schedule_render(&state.common.event_loop_handle, output)
            }
        }

        // send out events
        let display = state.common.display.clone();
        display.borrow_mut().flush_clients(state);
        // trigger routines
        state.common.shell.refresh();
        state.common.refresh_focus();
    })?;

    let _log = state.destroy();
    // drop eventloop before logger
    std::mem::drop(event_loop);

    Ok(())
}

fn init_wayland_display(event_loop: &mut EventLoop<state::State>) -> Result<(Display, OsString)> {
    let mut display = Display::new();
    let socket_name = display.add_socket_auto()?;

    slog_scope::info!("Listening on {:?}", socket_name);
    event_loop
        .handle()
        .insert_source(
            Generic::new(display.get_poll_fd(), Interest::READ, Mode::Level),
            move |_, _, state: &mut state::State| {
                let display = state.common.display.clone();
                let mut display = display.borrow_mut();
                match display.dispatch(std::time::Duration::from_millis(0), state) {
                    Ok(_) => Ok(PostAction::Continue),
                    Err(e) => {
                        slog_scope::error!("I/O error on the Wayland display: {}", e);
                        state.common.should_stop = true;
                        Err(e)
                    }
                }
            },
        )
        .with_context(|| "Failed to init the wayland event source.")?;

    Ok((display, socket_name))
}
