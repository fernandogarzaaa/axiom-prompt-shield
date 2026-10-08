//! `axiom-prompt-shield`: prompt injection security testing with AXIOM.
//!
//! Tests system prompts against a battery of injection attacks using local
//! heuristic scoring, and hardens vulnerable prompts through AXIOM's
//! transactional agent-task loop: proposed hardenings are applied
//! all-or-nothing and rolled back when the security verifier regresses.

mod attacks;
mod axiom;
mod hardening;
mod harness;
mod scorer;

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::axiom::{AxiomClient, FileEdit};
use crate::hardening::{HardeningLevel, harden};

/// Prompt injection security testing, hardened by AXIOM.
#[derive(Parser)]
#[command(name = "axiom-prompt-shield", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the injection battery against a prompt file and print the report.
    Test {
        /// Path to the system prompt file.
        prompt: PathBuf,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Verifier entrypoint: exit 0 iff the prompt scores >= MIN_SCORE.
    ///
    /// Designed to be used as AXIOM's `verify_cmd`. Prints the score and
    /// exits non-zero when the prompt is too vulnerable, which makes AXIOM
    /// roll the proposal back.
    Verify {
        /// Path to the system prompt file.
        prompt: PathBuf,
        /// Minimum acceptable overall score in [0.0, 1.0].
        #[arg(long, default_value_t = 0.8)]
        min_score: f64,
    },
    /// Harden a vulnerable prompt through AXIOM's transactional task loop.
    ///
    /// Spawns the real `axiom-agent-task` binary, starts a task with this
    /// binary's `verify` subcommand as verifier, and proposes increasingly
    /// strong hardenings. AXIOM applies each proposal transactionally and
    /// rolls back on verifier failure.
    Harden {
        /// Path to the system prompt file (edited in place on success).
        prompt: PathBuf,
        /// Minimum acceptable overall score in [0.0, 1.0].
        #[arg(long, default_value_t = 0.8)]
        min_score: f64,
        /// Maximum AXIOM attempts.
        #[arg(long, default_value_t = 6)]
        max_attempts: u64,
        /// Explicit path to the axiom-agent-task binary.
        #[arg(long)]
        axiom_bin: Option<PathBuf>,
    },
}

fn read_prompt(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn cmd_test(prompt: &Path, json: bool) -> Result<(), String> {
    let text = read_prompt(prompt)?;
    let report = harness::run_battery(&text);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", harness::render_text(&report));
    }
    Ok(())
}

fn cmd_verify(prompt: &Path, min_score: f64) -> Result<(), String> {
    let text = read_prompt(prompt)?;
    let report = harness::run_battery(&text);
    println!(
        "verify: score {:.3} (threshold {:.3}) -> {}",
        report.overall_score,
        min_score,
        if report.overall_score >= min_score {
            "PASS"
        } else {
            "FAIL"
        }
    );
    if report.overall_score >= min_score {
        Ok(())
    } else {
        Err(format!(
            "score {:.3} below threshold {:.3}",
            report.overall_score, min_score
        ))
    }
}

/// Run the AXIOM hardening workflow. Returns the number of proposals made.
fn cmd_harden(
    prompt: &Path,
    min_score: f64,
    max_attempts: u64,
    axiom_bin: Option<&Path>,
) -> Result<usize, String> {
    let prompt = prompt
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", prompt.display()))?;
    let workdir = prompt
        .parent()
        .ok_or_else(|| "prompt has no parent directory".to_string())?;
    let file_name = prompt
        .file_name()
        .ok_or_else(|| "prompt has no file name".to_string())?
        .to_string_lossy()
        .to_string();

    let binary = AxiomClient::find_binary(axiom_bin).ok_or_else(|| {
        "axiom-agent-task binary not found; pass --axiom-bin or set AXIOM_AGENT_TASK".to_string()
    })?;
    println!("AXIOM binary: {}", binary.display());

    // Baseline score before touching AXIOM.
    let base_text = read_prompt(&prompt)?;
    let base_report = harness::run_battery(&base_text);
    println!(
        "baseline score: {:.3} (blocked {}/{})",
        base_report.overall_score, base_report.attacks_blocked, base_report.attacks_tested
    );
    if base_report.overall_score >= min_score {
        println!("prompt already meets threshold; nothing to harden.");
        return Ok(0);
    }

    // The verifier is this binary itself, run from the task workdir.
    let self_exe = std::env::current_exe().map_err(|e| format!("cannot locate self: {e}"))?;
    let verify_cmd = format!(
        "\"{}\" verify \"{}\" --min-score {min_score}",
        self_exe.display(),
        file_name
    );

    let mut client =
        AxiomClient::spawn(&binary, workdir).map_err(|e| format!("AXIOM spawn: {e}"))?;
    let task_id = client
        .task_start(
            "harden system prompt against prompt injection",
            &verify_cmd,
            &[&file_name],
            max_attempts,
        )
        .map_err(|e| format!("task_start: {e}"))?;
    println!("task started: {task_id}");

    // Propose increasingly strong hardenings. The Basic duplicate exercises
    // AXIOM's fingerprint dedup: it is recorded but the verifier is not
    // re-run for it.
    let plan: &[(&str, HardeningLevel)] = &[
        ("basic hardening", HardeningLevel::Basic),
        ("basic hardening (duplicate)", HardeningLevel::Basic),
        ("standard hardening", HardeningLevel::Standard),
        ("full hardening", HardeningLevel::Full),
    ];

    let mut proposals = 0usize;
    let mut passed_any = false;
    for (label, level) in plan {
        let hardened = harden(&base_text, *level);
        let outcome = client
            .task_propose(
                &task_id,
                &[FileEdit {
                    path: file_name.clone(),
                    content: hardened,
                }],
            )
            .map_err(|e| format!("task_propose: {e}"))?;
        proposals += 1;
        println!(
            "attempt {} [{}]: passed={} fingerprint={}",
            outcome.attempt,
            label,
            outcome.passed,
            &outcome.fingerprint[..outcome.fingerprint.len().min(12)]
        );
        for line in outcome.output.lines().take(3) {
            println!("    | {line}");
        }
        if outcome.passed {
            passed_any = true;
        }
    }

    let history = client
        .task_history(&task_id)
        .map_err(|e| format!("task_history: {e}"))?;
    println!("\n--- task history ({} attempts) ---", history.len());
    for a in &history {
        let verdict = if a.passed { "PASS" } else { "FAIL" };
        let first_line = a.output.lines().next().unwrap_or("");
        println!(
            "attempt {}: {verdict} fp={} {first_line}",
            a.attempt,
            &a.fingerprint[..a.fingerprint.len().min(12)],
        );
    }

    let committed = client
        .task_finish(&task_id, true)
        .map_err(|e| format!("task_finish: {e}"))?;
    println!("\ntask finished, committed={committed}");

    let final_text = read_prompt(&prompt)?;
    let final_report = harness::run_battery(&final_text);
    println!(
        "final score: {:.3} (blocked {}/{})",
        final_report.overall_score, final_report.attacks_blocked, final_report.attacks_tested
    );
    if !passed_any {
        return Err("no proposal passed the verifier".to_string());
    }
    Ok(proposals)
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Test { prompt, json } => cmd_test(prompt, *json),
        Commands::Verify { prompt, min_score } => cmd_verify(prompt, *min_score),
        Commands::Harden {
            prompt,
            min_score,
            max_attempts,
            axiom_bin,
        } => cmd_harden(prompt, *min_score, *max_attempts, axiom_bin.as_deref()).map(|_| ()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
