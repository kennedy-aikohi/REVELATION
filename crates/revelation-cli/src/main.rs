use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use revelation_core::{
    rules_update::{update_rules, RuleSource, UpdateOptions},
    scan::{scan_files, ScanOptions},
    yara_engine::YaraEngine,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "revelation",
    version,
    about = "REVELATION - Local malware hunter (disk + YARA) with auto-updating rules"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    
    RulesUpdate {
        #[arg(long, value_enum, default_value = "community")]
        source: RuleSourceArg,

        
        #[arg(long)]
        accept_elastic_license_2_0: bool,

        
        #[arg(long, default_value = "rules")]
        rules_dir: PathBuf,
    },

    
    Scan {
        /// Path to scan
        #[arg(long)]
        path: PathBuf,

        
        #[arg(long)]
        rules_file: Option<PathBuf>,

        
        #[arg(long, default_value_t = 8)]
        threads: usize,

        
        #[arg(long)]
        hashes: bool,

        
        #[arg(long, default_value_t = 50)]
        max_mb: u64,

        
        #[arg(long, value_enum, default_value = "console")]
        output: OutputArg,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputArg {
    Console,
    Json,
}

#[derive(Clone, ValueEnum)]
enum RuleSourceArg {
    Community,
    Elastic,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::RulesUpdate {
            source,
            accept_elastic_license_2_0,
            rules_dir,
        } => {
            let src = match source {
                RuleSourceArg::Community => RuleSource::YaraRulesCommunity,
                RuleSourceArg::Elastic => RuleSource::ElasticProtectionsArtifacts,
            };

            let opts = UpdateOptions {
                rules_dir,
                accept_elastic_elv2: accept_elastic_license_2_0,
            };

            
            let res = update_rules(src, &opts)?;

            println!("[OK] Rules updated: {}", res.source_name);
            println!("     Repo URL:  {}", res.repo_url);
            println!("     Repo path: {}", res.repo_path.display());
            println!("     Commit:    {}", res.head_commit);
            println!("     Combined:  {}", res.combined_rules_path.display());
        }

        Commands::Scan {
            path,
            rules_file,
            threads,
            hashes,
            max_mb,
            output,
        } => {
            let rules =
                rules_file.unwrap_or_else(|| PathBuf::from("rules/compiled/community_combined.yar"));

            let engine = YaraEngine::from_rules_file(&rules)
                .with_context(|| format!("Compiling rules from {}", rules.display()))?;

            let report = scan_files(
                &engine,
                ScanOptions {
                    root: path,
                    threads,
                    compute_hashes: hashes,
                    max_file_size_mb: max_mb,
                    progress: None, 
                },
            )?;

            match output {
                OutputArg::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputArg::Console => {
                    print_console(report)?;
                }
            }
        }
    }

    Ok(())
}

fn print_console(report: revelation_core::report::ScanReport) -> Result<()> {
    println!("REVELATION report");
    println!("Started:  {}", report.started_utc);
    println!("Finished: {}", report.finished_utc);
    println!("Scanned files:  {}", report.scanned_files);
    println!("Matched files:  {}", report.matched_files);
    println!();

    for f in report.findings.iter().take(2000) {
        let sev = if f.score >= 85 {
            "HIGH"
        } else if f.score >= 60 {
            "MED"
        } else {
            "LOW"
        };

        println!(
            "[{}] {} (score {}, {} bytes)",
            sev,
            f.path.display(),
            f.score,
            f.size
        );

        if let Some(h) = &f.sha256 {
            println!("      sha256: {}", h);
        }

        for m in &f.yara {
            println!(
                "      YARA: {}  namespace={}  tags={:?}",
                m.rule, m.namespace, m.tags
            );

            if !m.meta.is_empty() {
                println!("        meta:");
                for (k, v) in &m.meta {
                    println!("          - {}: {}", k, v);
                }
            }

            
            if !m.strings.is_empty() {
                println!("        matched strings:");
                for s in m.strings.iter().take(20) {
                    println!(
                        "          - {} @0x{:x} \"{}\"",
                        s.identifier, s.offset, s.data_preview
                    );
                }
                if m.strings.len() > 20 {
                    println!("          ... ({} more)", m.strings.len() - 20);
                }
            }
        }

        println!();
    }

    Ok(())
}
