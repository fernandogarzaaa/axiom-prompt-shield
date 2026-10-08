//! End-to-end test of the AXIOM agent-task loop against the real binary.
//!
//! Requires the `axiom-agent-task` binary: set `AXIOM_AGENT_TASK` to its
//! path, or place it next to the test executable. Skipped silently when the
//! binary is absent (e.g. GitHub CI), so `cargo test` stays green everywhere.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn axiom_binary() -> Option<PathBuf> {
    if let Ok(var) = std::env::var("AXIOM_AGENT_TASK") {
        let p = PathBuf::from(var);
        if p.is_file() {
            return Some(p);
        }
    }
    // Common dev location: the AXIOM-AETHER checkout.
    let cand =
        "/home/hatch/workspace/audits/axiom-aether/axiom_engine_rs/target/release/axiom-agent-task";
    let p = PathBuf::from(cand);
    if p.is_file() {
        return Some(p);
    }
    None
}

struct Rpc {
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
    _child: std::process::Child,
}

impl Rpc {
    fn spawn(bin: &PathBuf, workdir: &std::path::Path) -> Self {
        let mut child = Command::new(bin)
            .current_dir(workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn axiom-agent-task");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
            _child: child,
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], json!(id));
        assert!(v.get("error").is_none(), "rpc error: {v}");
        v["result"].clone()
    }
}

#[test]
fn axiom_task_loop_propose_history_finish() {
    let bin = match axiom_binary() {
        Some(b) => b,
        None => {
            eprintln!("skipping: axiom-agent-task binary not found");
            return;
        }
    };
    let dir = tempfile_dir();
    fs::write(dir.join("prompt.txt"), "You are helpful.\n").unwrap();

    let mut rpc = Rpc::spawn(&bin, &dir);

    // task_start with a verifier that always passes.
    let started = rpc.call(
        "task_start",
        json!({"goal": "test", "verify_cmd": "true", "files": ["prompt.txt"], "max_attempts": 4}),
    );
    let task_id = started["task_id"].as_str().unwrap().to_string();
    assert!(!task_id.is_empty());

    // Failing proposal: verifier `false` always fails.
    let fail_task = rpc.call(
        "task_start",
        json!({"goal": "test-fail", "verify_cmd": "false", "files": ["prompt.txt"], "max_attempts": 4}),
    );
    let fail_id = fail_task["task_id"].as_str().unwrap().to_string();
    let r1 = rpc.call(
        "task_propose",
        json!({"task_id": fail_id, "edits": [{"path": "prompt.txt", "content": "changed\n"}]}),
    );
    assert_eq!(r1["passed"], json!(false));
    assert_eq!(r1["attempt"], json!(1));
    // File must be rolled back to the original.
    assert_eq!(
        fs::read_to_string(dir.join("prompt.txt")).unwrap(),
        "You are helpful.\n"
    );

    // Duplicate of the failed edit-set: rejected without re-running verifier.
    let r2 = rpc.call(
        "task_propose",
        json!({"task_id": fail_id, "edits": [{"path": "prompt.txt", "content": "changed\n"}]}),
    );
    assert_eq!(r2["passed"], json!(false));
    assert!(r2["output"].as_str().unwrap().contains("already rejected"));

    // Passing proposal on the first task.
    let r3 = rpc.call(
        "task_propose",
        json!({"task_id": task_id, "edits": [{"path": "prompt.txt", "content": "hardened\n"}]}),
    );
    assert_eq!(r3["passed"], json!(true));

    // History records attempts in order.
    let h = rpc.call("task_history", json!({"task_id": fail_id}));
    let attempts = h["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);

    // Finish with commit=false restores pre-task state even after a pass.
    let f = rpc.call("task_finish", json!({"task_id": task_id, "commit": false}));
    assert_eq!(f["committed"], json!(false));
    assert_eq!(
        fs::read_to_string(dir.join("prompt.txt")).unwrap(),
        "You are helpful.\n"
    );
}

fn tempfile_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shield-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}
