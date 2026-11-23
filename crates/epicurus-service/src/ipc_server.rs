//! Named-pipe IPC server.
//!
//! The pipe's DACL admits only SYSTEM, Administrators and the SID of the
//! interactive user who installed Epicurus; remote clients are rejected; the
//! first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` so another
//! process cannot squat the name before the service. Frames are size-capped
//! before allocation and every request is validated by the core protocol
//! before it reaches the engine.

use std::os::windows::io::AsRawHandle;
use std::time::Duration;

use epicurus_core::ipc::{
    IpcError, MAX_REQUEST_BYTES, PROTOCOL_VERSION, Reply, ReplyEnvelope, Request, decode_request,
    pipe_path,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, watch};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::engine::{Outcome, SharedEngine};

/// Serves clients until `shutdown` flips to true.
pub async fn serve(
    pipe_name: String,
    user_sid: Option<String>,
    engine: SharedEngine,
    events: broadcast::Sender<epicurus_core::ipc::Event>,
    mut shutdown: watch::Receiver<bool>,
) -> crate::error::Result<()> {
    let addr = pipe_path(&pipe_name);
    let sd = epicurus_sensor::security::Sd::from_sddl(&epicurus_sensor::security::pipe_sddl(
        user_sid.as_deref(),
    ))?;
    let mut first = true;
    loop {
        let server = {
            let mut sa = sd.attributes();
            // SAFETY: `sa` points at a descriptor owned by `sd`, which outlives
            // the call; the pipe keeps its own copy of the descriptor.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .reject_remote_clients(true)
                    .max_instances(32)
                    .in_buffer_size(64 * 1024)
                    .out_buffer_size(64 * 1024)
                    .create_with_security_attributes_raw(
                        &addr,
                        (&mut sa as *mut windows::Win32::Security::SECURITY_ATTRIBUTES).cast(),
                    )
            }
        }?;
        first = false;
        tokio::select! {
            r = server.connect() => {
                if let Err(e) = r {
                    tracing::debug!(error = %e, "pipe connect failed");
                    continue;
                }
                let engine = engine.clone();
                let events = events.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(server, engine, events).await {
                        tracing::debug!(error = %e, "IPC client ended");
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

fn client_pid(pipe: &NamedPipeServer) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: the handle is a connected server pipe owned by `pipe`.
    unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    Some(pid)
}

async fn write_reply(
    pipe: &mut NamedPipeServer,
    id: u64,
    reply: Reply,
) -> crate::error::Result<()> {
    let body = serde_json::to_vec(&ReplyEnvelope {
        v: PROTOCOL_VERSION,
        id,
        reply,
    })?;
    let mut buf = Vec::with_capacity(body.len() + 4);
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    pipe.write_all(&buf).await?;
    pipe.flush().await?;
    Ok(())
}

async fn handle_client(
    mut pipe: NamedPipeServer,
    engine: SharedEngine,
    mut events: broadcast::Receiver<epicurus_core::ipc::Event>,
) -> crate::error::Result<()> {
    let pid = client_pid(&pipe);
    loop {
        // An idle client is dropped after 10 minutes; the tray agent
        // reconnects automatically.
        let len = match tokio::time::timeout(Duration::from_secs(600), pipe.read_u32_le()).await {
            Ok(Ok(l)) => l,
            _ => return Ok(()),
        };
        if len > MAX_REQUEST_BYTES {
            write_reply(
                &mut pipe,
                0,
                Reply::Error(IpcError {
                    code: "bad_request".into(),
                    message: "request too large".into(),
                }),
            )
            .await?;
            return Ok(());
        }
        let mut body = vec![0u8; len as usize];
        tokio::time::timeout(Duration::from_secs(10), pipe.read_exact(&mut body)).await??;
        let env = match decode_request(&body) {
            Ok(e) => e,
            Err(e) => {
                write_reply(
                    &mut pipe,
                    0,
                    Reply::Error(IpcError {
                        code: "bad_request".into(),
                        message: e.to_string(),
                    }),
                )
                .await?;
                continue;
            }
        };
        if env.req == Request::Subscribe {
            write_reply(
                &mut pipe,
                env.id,
                Reply::Ok(epicurus_core::ipc::Response::Ack),
            )
            .await?;
            loop {
                match events.recv().await {
                    Ok(ev) => write_reply(&mut pipe, 0, Reply::Event(ev)).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        let eng = engine.clone();
        let outcome = tokio::task::spawn_blocking(move || match eng.lock() {
            Ok(mut e) => e.handle(env.req, pid),
            Err(_) => Outcome::Ready(Box::new(Err(IpcError {
                code: "internal".into(),
                message: "engine lock poisoned".into(),
            }))),
        })
        .await?;
        let reply = match outcome {
            Outcome::Ready(r) => match *r {
                Ok(r) => Reply::Ok(r),
                Err(e) => Reply::Error(e),
            },
            Outcome::AwaitTest(rx) => match tokio::time::timeout(Duration::from_secs(20), rx).await
            {
                Ok(Ok(Ok(detail))) => {
                    Reply::Ok(epicurus_core::ipc::Response::ActionResult { ok: true, detail })
                }
                Ok(Ok(Err(detail))) => {
                    Reply::Ok(epicurus_core::ipc::Response::ActionResult { ok: false, detail })
                }
                _ => Reply::Ok(epicurus_core::ipc::Response::ActionResult {
                    ok: false,
                    detail: "test timed out".into(),
                }),
            },
        };
        write_reply(&mut pipe, env.id, reply).await?;
    }
}
