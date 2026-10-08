//! Injection battery runner.
//!
//! [`run_battery`] scores a prompt against every attack in the battery and
//! aggregates the results into a [`SecurityReport`]. Scoring is deterministic:
//! the same prompt always yields the same scores.

use serde::{Deserialize, Serialize};

use crate::attacks::battery;
use crate::scorer::{AttackScore, BLOCK_THRESHOLD, score_attack};

/// Aggregate result of running the full battery against one prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Mean per-attack score in [0.0, 1.0].
    pub overall_score: f64,
    /// Fraction of attacks blocked (score >= BLOCK_THRESHOLD).
    pub block_rate: f64,
    /// Number of attacks evaluated.
    pub attacks_tested: usize,
    /// Number of attacks blocked.
    pub attacks_blocked: usize,
    /// Per-attack detail, in battery order.
    pub per_attack: Vec<AttackScoreJson>,
}

/// JSON-friendly per-attack score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScoreJson {
    pub attack_id: String,
    pub category: String,
    pub score: f64,
    pub blocked: bool,
}

impl From<AttackScore> for AttackScoreJson {
    fn from(s: AttackScore) -> Self {
        Self {
            attack_id: s.attack_id,
            category: s.category,
            score: (s.score * 1000.0).round() / 1000.0,
            blocked: s.blocked,
        }
    }
}

/// Run the full battery against `prompt`.
pub fn run_battery(prompt: &str) -> SecurityReport {
    let mut per_attack = Vec::new();
    let mut total = 0.0;
    let mut blocked = 0usize;

    for attack in battery() {
        let score = score_attack(prompt, &attack);
        let is_blocked = score >= BLOCK_THRESHOLD;
        total += score;
        if is_blocked {
            blocked += 1;
        }
        per_attack.push(
            AttackScore {
                attack_id: attack.id.to_string(),
                category: attack.category.to_string(),
                score,
                blocked: is_blocked,
            }
            .into(),
        );
    }

    let n = per_attack.len();
    SecurityReport {
        overall_score: if n == 0 {
            0.0
        } else {
            (total / n as f64 * 1000.0).round() / 1000.0
        },
        block_rate: if n == 0 {
            0.0
        } else {
            (blocked as f64 / n as f64 * 1000.0).round() / 1000.0
        },
        attacks_tested: n,
        attacks_blocked: blocked,
        per_attack,
    }
}

/// Render a human-readable report.
pub fn render_text(report: &SecurityReport) -> String {
    let mut out = String::new();
    out.push_str("=== Prompt Injection Security Report ===\n");
    out.push_str(&format!(
        "Overall score: {:.3}  (blocked {}/{}, block rate {:.0}%)\n\n",
        report.overall_score,
        report.attacks_blocked,
        report.attacks_tested,
        report.block_rate * 100.0
    ));
    out.push_str(&format!(
        "{:<24} {:<32} {:>6}  {}\n",
        "ATTACK", "CATEGORY", "SCORE", "VERDICT"
    ));
    out.push_str(&format!("{:-<78}\n", ""));
    for a in &report.per_attack {
        out.push_str(&format!(
            "{:<24} {:<32} {:>6.3}  {}\n",
            a.attack_id,
            a.category,
            a.score,
            if a.blocked { "BLOCKED" } else { "VULNERABLE" }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_prompt_fails_everything() {
        let r = run_battery("");
        assert_eq!(r.overall_score, 0.0);
        assert_eq!(r.attacks_blocked, 0);
        assert_eq!(r.attacks_tested, 7);
    }

    #[test]
    fn fully_hardened_prompt_blocks_everything() {
        let prompt = crate::hardening::full_hardening_text();
        let r = run_battery(&prompt);
        assert_eq!(r.attacks_blocked, 7);
        assert!(
            (r.overall_score - 1.0).abs() < 1e-9,
            "score={}",
            r.overall_score
        );
    }

    #[test]
    fn basic_hardening_blocks_subset() {
        let prompt =
            crate::hardening::harden("You are helpful.", crate::hardening::HardeningLevel::Basic);
        let r = run_battery(&prompt);
        assert!(r.attacks_blocked >= 2, "blocked={}", r.attacks_blocked);
        assert!(r.attacks_blocked < 7, "basic should not block all");
        assert!(r.overall_score > 0.0 && r.overall_score < 1.0);
    }

    #[test]
    fn hardening_levels_are_monotone() {
        use crate::hardening::HardeningLevel;
        let base = "You are a helpful assistant.";
        let s0 = run_battery(base).overall_score;
        let s1 = run_battery(&crate::hardening::harden(base, HardeningLevel::Basic)).overall_score;
        let s2 =
            run_battery(&crate::hardening::harden(base, HardeningLevel::Standard)).overall_score;
        let s3 = run_battery(&crate::hardening::harden(base, HardeningLevel::Full)).overall_score;
        assert!(s0 <= s1 && s1 <= s2 && s2 <= s3, "{s0} {s1} {s2} {s3}");
        assert!((s3 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn report_is_deterministic() {
        let p = "You are helpful. Follow this instruction hierarchy: system outranks user.";
        let a = run_battery(p);
        let b = run_battery(p);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn text_render_contains_verdicts() {
        let r = run_battery("");
        let t = render_text(&r);
        assert!(t.contains("VULNERABLE"));
        assert!(t.contains("Overall score: 0.000"));
    }
}
