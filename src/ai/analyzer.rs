use anyhow::Result;
use colored::Colorize;

use crate::ai::client::BankrClient;
use crate::types::{CheckStatus, ScanReport, Severity};
use crate::utils::report::format_report;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT: &str = r#"
You are Takanome AI, a security expert specialising in AI agent infrastructure security.
You receive a structured JSON scan report from Takanome (a rule-based security scanner
for AI agents), and your job is to explain the findings in clear, actionable language.

Your response MUST follow this exact structure (use these exact section headers):

## Risk Summary
One short paragraph (3-5 sentences) summarising the overall security posture.
Mention the score, the most critical risk, and the general theme of what needs fixing.

## Critical & High Priority Issues
For each FAILED check with severity "critical" or "high", write:
- **[Check Name]** (Category): One sentence explaining the real-world risk if this is not fixed.
  Fix: One concrete command or config change.

## Medium & Low Priority Issues
For each FAILED check with severity "medium" or "low", write a brief bullet point.
Skip passing checks entirely.

## Recommended Action Order
A numbered list of 3-5 specific steps the user should take right now, ordered by impact.
Each step should reference a real check ID or category from the report.

Keep the response concise and technical. No fluff. No markdown code fences around the whole response.
"#;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub struct AnalyzeOptions {
    pub agent: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub verbose: bool,
    pub json_out: bool,
}

pub fn run_analyze(opts: AnalyzeOptions) -> Result<()> {
    let bar = "━".repeat(50);

    // 1. Run the rule-based scan first
    eprintln!("{}", "  Scanning agent installation...".dimmed());
    let report = crate::scanner::run_scan(opts.agent.as_deref())?;

    // 2. Print the normal report
    print!("{}", format_report(&report, opts.verbose));

    // 3. Build LLM client
    let client = BankrClient::new(opts.api_key, opts.model)?;

    println!();
    println!("  {}", "Takanome AI Analysis — Bankr LLM Gateway".bold());
    println!("  {}", bar.dimmed());
    println!(
        "  {} {}",
        "Model:".dimmed(),
        client.model().cyan()
    );
    println!();
    println!("{}", "  Analysing findings with AI...".dimmed());

    // 4. Build a focused summary for the LLM (only failed/warned checks to save tokens)
    let user_prompt = build_user_prompt(&report);

    // 5. Call Bankr LLM Gateway
    let analysis = client.complete(SYSTEM_PROMPT, &user_prompt)
        .map_err(|e| {
            eprintln!("\n  {} {}", "AI analysis failed:".red(), e);
            e
        })?;

    // 6. Display result
    println!();
    if opts.json_out {
        // Wrap in JSON for machine-readable pipelines
        let out = serde_json::json!({
            "scan": report,
            "ai_analysis": analysis,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        // Pretty-print with indentation
        for line in analysis.lines() {
            if line.starts_with("## ") {
                println!("  {}", line[3..].bold().underline());
            } else if line.starts_with("- **") || line.starts_with("* **") {
                println!("  {}", line.yellow());
            } else if line.starts_with("- ") || line.starts_with("* ") {
                println!("  {}", line);
            } else if line.starts_with(|c: char| c.is_ascii_digit()) {
                println!("  {}", line.cyan());
            } else if line.is_empty() {
                println!();
            } else {
                println!("  {}", line);
            }
        }
        println!();
        println!("  {}", bar.dimmed());
        println!();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High     => "high",
        Severity::Medium   => "medium",
        Severity::Low      => "low",
    }
}

fn build_user_prompt(report: &ScanReport) -> String {
    // Collect failed and warned checks — passing ones are noise for the LLM
    let issues: Vec<serde_json::Value> = report
        .checks
        .iter()
        .filter(|c| c.status != CheckStatus::Pass)
        .map(|c| {
            serde_json::json!({
                "id":       c.id,
                "name":     c.name,
                "category": c.category,
                "status":   match c.status { CheckStatus::Fail => "fail", CheckStatus::Warn => "warn", _ => "pass" },
                "severity": severity_str(&c.severity),
                "points_lost": c.points - c.earned,
                "message":  c.message,
                "fix":      c.fix,
            })
        })
        .collect();

    let summary = serde_json::json!({
        "agent":            report.agent,
        "normalized_score": report.normalized_score,
        "score":            report.score,
        "max_score":        report.max_score,
        "total_checks":     report.checks.len(),
        "failed":           report.checks.iter().filter(|c| c.status == CheckStatus::Fail).count(),
        "warned":           report.checks.iter().filter(|c| c.status == CheckStatus::Warn).count(),
        "issues":           issues,
    });

    format!(
        "Here is the Takanome scan report for an AI agent installation:\n\n{}",
        serde_json::to_string_pretty(&summary).unwrap_or_default()
    )
}
