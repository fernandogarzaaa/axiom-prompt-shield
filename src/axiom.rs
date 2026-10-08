//! Minimal JSON-RPC 2.0 client for the `axiom-agent-task` binary.
//!
//! Spawns the real AXIOM binary as a child process and speaks the
//! line-delimited JSON-RPC protocol over its stdio: `task_start`,
//! `task_propose`, `task_history`, `task_finish`. A background reader thread
//! forwards response lines through a channel so reads can time out instead
//! of hanging forever on a wedged server.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

/// Response timeout per RPC round-trip.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Errors from the AXIOM client.
#[derive(Debug)]
pub enum AxiomError {
    /// The binary could not be spawned.
    Spawn(String),
    /// Stdio plumbing failed.
    Io(String),
    /// No response arrived within [`RPC_TIMEOUT`].
    Timeout,
    /// The response was not valid JSON-RPC.
    BadResponse(String),
    /// The server returned a JSON-RPC error object.
    Server { code: i32, message: String },
    /// Response id did not match the request id.
    IdMismatch,
}

impl std::fmt::Display for AxiomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AxiomError::Spawn(e) => write!(f, "failed to spawn axiom-agent-task: {e}"),
            AxiomError::Io(e) => write!(f, "stdio error: {e}"),
            AxiomError::Timeout => write!(f, "timed out waiting for axiom-agent-task"),
            AxiomError::BadResponse(e) => write!(f, "bad response: {e}"),
            AxiomError::Server { code, message } => {
                write!(f, "server error {code}: {message}")
            }
            AxiomError::IdMismatch => write!(f, "response id did not match request id"),
        }
    }
}

impl std::error::Error for AxiomError {}

/// A single file edit proposed to AXIOM.
#[derive(Debug, Clone)]
pub struct FileEdit {
    pub path: String,
    pub content: String,
}

/// Outcome of one `task_propose` call.
#[derive(Debug, Clone)]
pub struct ProposalOutcome {
    pub passed: bool,
    pub attempt: u64,
    pub output: String,
    pub fingerprint: String,
}

/// One recorded attempt from `task_history`.
#[derive(Debug, Clone)]
pub struct AttemptRecord {
    pub attempt: u64,
    pub fingerprint: String,
    pub passed: bool,
    pub output: String,
}

/// Client handle for a running `axiom-agent-task` server.
pub struct AxiomClient {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<std::io::Result<String>>,
    reader: Option<JoinHandle<()>>,
    next_id: u64,
}

impl AxiomClient {
    /// Spawn the binary. `workdir` becomes the server's working directory:
    /// the verifier command runs there and `files` paths resolve there.
    pub fn spawn(binary: &Path, workdir: &Path) -> Result<Self, AxiomError> {
        let mut child = Command::new(binary)
            .current_dir(workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| AxiomError::Spawn(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AxiomError::Spawn("stdin not captured".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AxiomError::Spawn("stdout not captured".into()))?;
        let (sender, responses) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            responses,
            reader: Some(reader),
            next_id: 1,
        })
    }

    /// Send one request and return the `result` value.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, AxiomError> {
        let id = self.next_id;
        self.next_id += 1;
        let line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| AxiomError::Io("stdin closed".into()))?;
        writeln!(stdin, "{line}").map_err(|e| AxiomError::Io(e.to_string()))?;
        stdin.flush().map_err(|e| AxiomError::Io(e.to_string()))?;

        let line = self
            .responses
            .recv_timeout(RPC_TIMEOUT)
            .map_err(|_| AxiomError::Timeout)?
            .map_err(|e| AxiomError::Io(e.to_string()))?;
        let response: Value =
            serde_json::from_str(&line).map_err(|e| AxiomError::BadResponse(e.to_string()))?;
        if response.get("jsonrpc") != Some(&json!("2.0")) {
            return Err(AxiomError::BadResponse("missing jsonrpc 2.0".into()));
        }
        if response.get("id") != Some(&json!(id)) {
            return Err(AxiomError::IdMismatch);
        }
        if let Some(err) = response.get("error") {
            return Err(AxiomError::Server {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0) as i32,
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| AxiomError::BadResponse("missing result".into()))
    }

    /// Start a task. Returns the server-assigned task id.
    pub fn task_start(
        &mut self,
        goal: &str,
        verify_cmd: &str,
        files: &[&str],
        max_attempts: u64,
    ) -> Result<String, AxiomError> {
        let result = self.request(
            "task_start",
            json!({"goal": goal, "verify_cmd": verify_cmd, "files": files, "max_attempts": max_attempts}),
        )?;
        result
            .get("task_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| AxiomError::BadResponse("missing task_id".into()))
    }

    /// Propose an edit set for a task.
    pub fn task_propose(
        &mut self,
        task_id: &str,
        edits: &[FileEdit],
    ) -> Result<ProposalOutcome, AxiomError> {
        let edits_json: Vec<Value> = edits
            .iter()
            .map(|e| json!({"path": e.path, "content": e.content}))
            .collect();
        let result = self.request(
            "task_propose",
            json!({"task_id": task_id, "edits": edits_json}),
        )?;
        Ok(ProposalOutcome {
            passed: bool_from(&result, "passed"),
            attempt: result.get("attempt").and_then(Value::as_u64).unwrap_or(0),
            output: str_from(&result, "output"),
            fingerprint: str_from(&result, "fingerprint"),
        })
    }

    /// Fetch the attempt history for a task.
    pub fn task_history(&mut self, task_id: &str) -> Result<Vec<AttemptRecord>, AxiomError> {
        let result = self.request("task_history", json!({"task_id": task_id}))?;
        let attempts = result
            .get("attempts")
            .and_then(Value::as_array)
            .ok_or_else(|| AxiomError::BadResponse("missing attempts".into()))?;
        attempts
            .iter()
            .map(|a| {
                Ok(AttemptRecord {
                    attempt: a.get("attempt").and_then(Value::as_u64).unwrap_or(0),
                    fingerprint: str_from(a, "fingerprint"),
                    passed: bool_from(a, "passed"),
                    output: str_from(a, "output"),
                })
            })
            .collect()
    }

    /// Finish a task. `commit=true` keeps the last passing edits on disk;
    /// `commit=false` restores the pre-task file contents.
    pub fn task_finish(&mut self, task_id: &str, commit: bool) -> Result<bool, AxiomError> {
        let result = self.request("task_finish", json!({"task_id": task_id, "commit": commit}))?;
        Ok(bool_from(&result, "committed"))
    }

    /// Locate the `axiom-agent-task` binary: explicit path first, then the
    /// `AXIOM_AGENT_TASK` env var, then alongside the current executable.
    pub fn find_binary(explicit: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = explicit
            && p.is_file()
        {
            return Some(p.to_path_buf());
        }
        if let Ok(var) = std::env::var("AXIOM_AGENT_TASK") {
            let p = PathBuf::from(var);
            if p.is_file() {
                return Some(p);
            }
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let p = dir.join("axiom-agent-task");
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }
}

fn str_from(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn bool_from(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

impl Drop for AxiomClient {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
