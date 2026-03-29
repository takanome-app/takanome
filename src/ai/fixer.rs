use anyhow::Result;
use colored::Colorize;
use serde::Deserialize;

use crate::ai::client::BankrClient;
use crate::types::{CheckStatus, ScanReport, Severity};

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT: &str = r#"
You are Takanome AI Fix, a security remediation engine for AI agent infrastructure.
You receive a JSON scan report and must return a JSON array of fix actions.

RESPOND WITH ONLY A JSON ARRAY. No markdown, no explanation outside the JSON.

Each element in the array must have:
{
  "check_id":    string   — the check ID from the report,
  "check_name":  string   — human-readable check name,
  "severity":    string   — "critical" | "high" | "medium" | "low",
  "risk":        string   — one sentence: what can go wrong if not fixed,
  "action_type": string   — one of: "config_set" | "permission" | "token_gen" | "manual",
  "description": string   — what this fix does (one sentence),
  "command":     string   — the exact shell command or config snippet to apply,
                           OR null if action_type is "manual",
  "manual_steps": string  — step-by-step instructions if action_type is "manual", else null,
  "priority":    integer  — 1 (do first) to 5 (do last)
}

Rules:
- Only include failed checks (status: "fail"). Skip warnings and passes.
- For config_set: provide the exact JSON path and value, e.g. `openclaw config set gateway.auth_mode token`
- For permission: provide the exact chmod command
- For token_gen: provide the command to generate a strong token
- For manual: explain step-by-step in manual_steps, set command to null
- Order by priority: critical first (1), then high (2), medium (3-4), low (5)
- Be precise. Never suggest "consider" or "you might". Give exact commands.
"#;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AiFixAction {
    pub check_id:     String,
    pub check_name:   String,
    pub severity:     String,
    pub risk:         String,
    pub action_type:  String,
    pub description:  String,
    pub command:      Option<String>,
    pub manual_steps: Option<String>,
    pub priority:     u8,
}

pub struct AiFixOptions {
    pub agent:       Option<String>,
    pub api_key:     Option<String>,
    pub model:       Option<String>,
    pub dry_run:     bool,
    pub interactive: bool,
    pub verbose:     bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run_ai_fix(opts: AiFixOptions) -> Result<()> {
    let bar = "━".repeat(50);

    eprintln!("{}", "  Scanning agent installation...".dimmed());
    let report = crate::scanner::run_scan(opts.agent.as_deref())?;

    let failed_count = report.checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
    if failed_count == 0 {
        println!();
        println!("  {}", "Takanome AI Fix — OpenClaw".bold());
        println!("  {}", bar.dimmed());
        println!();
        println!("  {} No failed checks to fix!", "✓".green());
        println!();
        return Ok(());
    }

    let client = BankrClient::new(opts.api_key, opts.model)?;

    println!();
    println!("  {}", "Takanome AI Fix — Bankr LLM Gateway".bold());
    println!("  {}", bar.dimmed());
    println!(
        "  {} {}   {} {}",
        "Model:".dimmed(),
        client.model().cyan(),
        "Failed checks:".dimmed(),
        failed_count.to_string().red().bold()
    );
    if opts.dry_run {
        println!("  {}", "[DRY RUN — no changes will be made]".yellow().bold());
    }
    println!();
    println!("{}", "  Generating AI fix plan...".dimmed());

    let user_prompt = build_user_prompt(&report);
    let raw = client.complete(SYSTEM_PROMPT, &user_prompt)?;

    // Strip potential markdown fences
    let json_str = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let mut actions: Vec<AiFixAction> = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("AI returned invalid JSON: {}\n\nRaw response:\n{}", e, raw))?;

    // Sort by priority just in case
    actions.sort_by_key(|a| a.priority);

    if actions.is_empty() {
        println!("  {} AI found no actionable fixes.", "ℹ".cyan());
        return Ok(());
    }

    println!();
    println!("  {} fix actions generated\n", actions.len().to_string().bold());

    let mut applied = 0usize;
    let mut skipped = 0usize;

    for (i, action) in actions.iter().enumerate() {
        print_action(i + 1, &action);

        if opts.dry_run {
            println!("  {} Skipped (dry run)\n", "↷".dimmed());
            skipped += 1;
            continue;
        }

        if opts.interactive {
            print!("  Apply this fix? [Y/n] ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();
            if input == "n" || input == "no" {
                println!("  {} Skipped\n", "↷".yellow());
                skipped += 1;
                continue;
            }
        }

        match apply_action(&action) {
            Ok(msg) => {
                println!("  {} {}\n", "✓".green(), msg);
                applied += 1;
            }
            Err(e) => {
                println!("  {} {}\n", "✗".red(), e);
                skipped += 1;
            }
        }
    }

    // Final score delta
    println!("  {}", bar.dimmed());
    if opts.dry_run {
        println!(
            "  Dry run complete — {} actions would be applied",
            actions.len()
        );
    } else {
        println!(
            "  {} applied, {} skipped",
            applied.to_string().green(),
            skipped.to_string().yellow()
        );
        if applied > 0 {
            println!();
            println!("  {} Run {} to see updated score",
                "→".cyan(),
                "takanome scan".bold()
            );
        }
    }
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_color(s: &str) -> colored::Color {
    match s {
        "critical" => colored::Color::Red,
        "high"     => colored::Color::Red,
        "medium"   => colored::Color::Yellow,
        _          => colored::Color::White,
    }
}

fn print_action(n: usize, action: &AiFixAction) {
    let sev = action.severity.to_uppercase();
    let sev_colored = sev.color(severity_color(&action.severity)).bold();

    println!(
        "  {}. [{}] {}",
        n,
        sev_colored,
        action.check_name.bold()
    );
    println!("     {}", action.risk.dimmed());
    println!("     {} {}", "→".cyan(), action.description);

    if let Some(cmd) = &action.command {
        println!("     {}", cmd.cyan());
    }
    if let Some(steps) = &action.manual_steps {
        for (i, step) in steps.lines().enumerate() {
            if !step.trim().is_empty() {
                println!("     {}. {}", i + 1, step.trim());
            }
        }
    }
    println!();
}

fn apply_action(action: &AiFixAction) -> Result<String> {
    match action.action_type.as_str() {
        "permission" => {
            if let Some(cmd) = &action.command {
                run_shell(cmd)
            } else {
                Ok("No command provided — skipped".to_string())
            }
        }
        "config_set" => {
            if let Some(cmd) = &action.command {
                run_shell(cmd)
            } else {
                Ok("No command provided — skipped".to_string())
            }
        }
        "token_gen" => {
            if let Some(cmd) = &action.command {
                run_shell(cmd)
            } else {
                Ok("No command provided — skipped".to_string())
            }
        }
        "manual" => {
            Ok("Manual action — see instructions above".to_string())
        }
        _ => {
            Ok(format!("Unknown action type '{}' — skipped", action.action_type))
        }
    }
}

fn run_shell(cmd: &str) -> Result<String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run command: {}", e))?;

    if output.status.success() {
        Ok(format!("Command succeeded: {}", cmd))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!(
            "Command failed: {}\n  stderr: {}",
            cmd,
            stderr.trim()
        ))
    }
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High     => "high",
        Severity::Medium   => "medium",
        Severity::Low      => "low",
    }
}

fn build_user_prompt(report: &ScanReport) -> String {
    let failed: Vec<serde_json::Value> = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .map(|c| {
            serde_json::json!({
                "id":          c.id,
                "name":        c.name,
                "category":    c.category,
                "severity":    severity_str(&c.severity),
                "points_lost": c.points - c.earned,
                "message":     c.message,
                "fix_hint":    c.fix,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "agent":            report.agent,
        "normalized_score": report.normalized_score,
        "failed_checks":    failed,
    });

    format!(
        "Generate fix actions for these failed security checks:\n\n{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    )
}
