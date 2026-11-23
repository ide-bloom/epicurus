//! Background IPC worker for the dashboard: requests are queued from the
//! UI thread and answered asynchronously so the UI never blocks on the pipe.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};

use epicurus_core::ipc::{Client, Request, Response};

/// Checks that a connected pipe really belongs to the Epicurus service
/// (defends against a squatted pipe name).
pub type Verifier = Arc<dyn Fn(&Client) -> bool + Send + Sync>;

/// A tagged request.
pub struct Job {
    /// Caller-defined tag to route the answer.
    pub tag: &'static str,
    /// Request.
    pub req: Request,
}

/// A tagged answer.
pub struct Answer {
    /// Tag from the job.
    pub tag: &'static str,
    /// Result.
    pub result: Result<Response, String>,
}

/// Handle owned by the UI thread.
pub struct Worker {
    tx: Sender<Job>,
    rx: Receiver<Answer>,
}

impl Worker {
    /// Spawns the worker thread. `wake` is called after every answer so the
    /// UI can repaint.
    pub fn spawn(pipe: String, verifier: Verifier, wake: impl Fn() + Send + 'static) -> Self {
        let (tx, job_rx) = std::sync::mpsc::channel::<Job>();
        let (ans_tx, rx) = std::sync::mpsc::channel::<Answer>();
        std::thread::spawn(move || {
            let mut client: Option<Client> = None;
            while let Ok(job) = job_rx.recv() {
                if client.is_none() {
                    client = match Client::connect(&pipe) {
                        Ok(c) if verifier(&c) => Some(c),
                        Ok(_) => {
                            let _ = ans_tx.send(Answer {
                                tag: job.tag,
                                result: Err(
                                    "refusing to talk to a pipe not owned by the Epicurus service"
                                        .into(),
                                ),
                            });
                            wake();
                            continue;
                        }
                        Err(e) => {
                            let _ = ans_tx.send(Answer {
                                tag: job.tag,
                                result: Err(e.to_string()),
                            });
                            wake();
                            continue;
                        }
                    };
                }
                let result = match client.as_mut().map(|c| c.call(job.req)) {
                    Some(Ok(r)) => Ok(r),
                    Some(Err(e)) => {
                        // Drop the connection on transport errors so the next
                        // job reconnects (e.g. after a service restart).
                        if matches!(e, epicurus_core::Error::IoBare(_)) {
                            client = None;
                        }
                        Err(e.to_string())
                    }
                    None => Err("not connected".into()),
                };
                let _ = ans_tx.send(Answer {
                    tag: job.tag,
                    result,
                });
                wake();
            }
        });
        Self { tx, rx }
    }

    /// Queues a request.
    pub fn send(&self, tag: &'static str, req: Request) {
        let _ = self.tx.send(Job { tag, req });
    }

    /// Drains available answers.
    pub fn poll(&self) -> Vec<Answer> {
        let mut out = Vec::new();
        while let Ok(a) = self.rx.try_recv() {
            out.push(a);
        }
        out
    }
}
