mod agents;
mod ai;
mod fixer;
mod scanner;
mod types;
mod utils;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use utils::report::{format_json, format_report};

#[derive(Parser)]
#[command(name = "takanome", about = "Security scanner for AI agents", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an AI agent installation for security risks
    Scan {
        /// Agent type to scan (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Show all checks including passing ones
        #[arg(long)]
        verbose: bool,
    },

    /// Auto-remediate security issues found by scan
    Fix {
        /// Agent type (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Show what would change without modifying anything
        #[arg(long)]
        dry_run: bool,

        /// Prompt before each fix [Y/n]
        #[arg(long)]
        interactive: bool,

        /// Show detailed output
        #[arg(long)]
        verbose: bool,

        /// Custom backup directory (default: ~/.takanome/backups/)
        #[arg(long)]
        backup_dir: Option<PathBuf>,
    },

    /// Scan and get AI-powered analysis of security risks (via Bankr LLM Gateway)
    Analyze {
        /// Agent type to scan (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Bankr API key (or set BANKR_API_KEY env var)
        #[arg(long)]
        api_key: Option<String>,

        /// LLM model to use (default: claude-haiku-4.5)
        /// Examples: claude-haiku-4.5, claude-sonnet-4.6, gemini-3-flash, gpt-5-nano
        #[arg(long)]
        model: Option<String>,

        /// Show all checks including passing ones
        #[arg(long)]
        verbose: bool,

        /// Output as JSON (scan + AI analysis combined)
        #[arg(long)]
        json: bool,
    },

    /// Scan and apply AI-generated smart fixes (via Bankr LLM Gateway)
    AiFix {
        /// Agent type to scan (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Bankr API key (or set BANKR_API_KEY env var)
        #[arg(long)]
        api_key: Option<String>,

        /// LLM model to use (default: claude-haiku-4.5)
        /// Examples: claude-haiku-4.5, claude-sonnet-4.6, gemini-3-flash, gpt-5-nano
        #[arg(long)]
        model: Option<String>,

        /// Show what would be fixed without applying changes
        #[arg(long)]
        dry_run: bool,

        /// Prompt before each fix [Y/n]
        #[arg(long)]
        interactive: bool,

        /// Show detailed output
        #[arg(long)]
        verbose: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { agent, json, verbose } => {
            match scanner::run_scan(agent.as_deref()) {
                Ok(report) => {
                    if json {
                        println!("{}", format_json(&report));
                    } else {
                        print!("{}", format_report(&report, verbose));
                    }

                    let critical_fails = report
                        .checks
                        .iter()
                        .filter(|c| {
                            c.status == types::CheckStatus::Fail
                                && c.severity == types::Severity::Critical
                        })
                        .count();

                    if critical_fails > 0 {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::Fix {
            agent,
            dry_run,
            interactive,
            verbose,
            backup_dir,
        } => {
            let opts = fixer::FixOptions {
                agent,
                dry_run,
                interactive,
                verbose,
                backup_dir,
            };
            if let Err(e) = fixer::run_fix(opts) {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }

        Commands::Analyze {
            agent,
            api_key,
            model,
            verbose,
            json,
        } => {
            let opts = ai::analyzer::AnalyzeOptions {
                agent,
                api_key,
                model,
                verbose,
                json_out: json,
            };
            if let Err(e) = ai::analyzer::run_analyze(opts) {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }

        Commands::AiFix {
            agent,
            api_key,
            model,
            dry_run,
            interactive,
            verbose,
        } => {
            let opts = ai::fixer::AiFixOptions {
                agent,
                api_key,
                model,
                dry_run,
                interactive,
                verbose,
            };
            if let Err(e) = ai::fixer::run_ai_fix(opts) {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }
    }
}
