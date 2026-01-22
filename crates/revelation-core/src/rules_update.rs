use anyhow::{bail, Context, Result};
use git2::{FetchOptions, Repository};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum RuleSource {
    YaraRulesCommunity,
    ElasticProtectionsArtifacts,
    HayabusaRules,
}

#[derive(Debug, Clone)]
pub struct UpdateOptions {
    pub rules_dir: PathBuf,
    pub accept_elastic_elv2: bool,
}

#[derive(Debug, Clone)]
pub struct RulesUpdateResult {
    pub source_name: String,
    pub repo_url: String,
    pub head_commit: String,
    pub combined_rules_path: PathBuf,
}

pub fn update_rules(source: RuleSource, opts: &UpdateOptions) -> Result<RulesUpdateResult> {
    let (source_name, repo_url, dest_folder, combined_out) = match source {
        RuleSource::YaraRulesCommunity => (
            "community".to_string(),
            "https://github.com/Yara-Rules/rules.git".to_string(),
            opts.rules_dir.join("repos").join("yara-rules-community"),
            opts.rules_dir.join("compiled").join("community_combined.yar"),
        ),
        RuleSource::ElasticProtectionsArtifacts => {
            if !opts.accept_elastic_elv2 {
                bail!("Elastic rules require --accept-elastic-license-2-0 (ELv2). You must explicitly accept the license to download these rules.");
            }

            (
                "elastic".to_string(),
                "https://github.com/elastic/protections-artifacts.git".to_string(),
                opts.rules_dir.join("repos").join("elastic-protections-artifacts"),
                opts.rules_dir.join("compiled").join("elastic_combined.yar"),
            )
        }
        RuleSource::HayabusaRules => (
            "hayabusa".to_string(),
            "https://github.com/Yamato-Security/hayabusa-rules.git".to_string(),
            opts.rules_dir.join("repos").join("hayabusa-rules"),
            opts.rules_dir
                .join("sigma_compiled")
                .join("hayabusa_rules_dir.marker"),
        ),
    };

    fs::create_dir_all(dest_folder.parent().unwrap())
        .context("Failed to create rules repo parent dir")?;
    fs::create_dir_all(combined_out.parent().unwrap())
        .context("Failed to create compiled rules dir")?;

    let repo = open_or_clone_repo(&repo_url, &dest_folder)?;
    fetch_origin(&repo)?;

    let head_commit = head_short_commit(&repo)?;

    let combined_rules_path = match source {
        RuleSource::HayabusaRules => {
            // We do not compile sigma rules into a single file.
            // Just mark success so the GUI can show repo + commit pulled.
            fs::write(&combined_out, &head_commit)
                .with_context(|| format!("Failed writing {}", combined_out.display()))?;
            combined_out.clone()
        }
        _ => combine_yara_files(&dest_folder, &combined_out)?,
    };

    Ok(RulesUpdateResult {
        source_name,
        repo_url,
        head_commit,
        combined_rules_path,
    })
}

fn open_or_clone_repo(repo_url: &str, dest: &Path) -> Result<Repository> {
    if dest.exists() {
        Repository::open(dest).context("Failed to open existing rules repo")
    } else {
        Repository::clone(repo_url, dest).context("Failed to clone rules repo")
    }
}

fn fetch_origin(repo: &Repository) -> Result<()> {
    {
        let mut remote = repo.find_remote("origin").context("No remote 'origin'")?;

        let mut fo = FetchOptions::new();
        remote
            .fetch(&["refs/heads/*:refs/remotes/origin/*"], Some(&mut fo), None)
            .context("Fetch failed")?;
    }

    Ok(())
}

fn head_short_commit(repo: &Repository) -> Result<String> {
    let head = repo.head().context("No HEAD")?;
    let oid = head.target().context("HEAD has no target")?;
    let full = oid.to_string();
    Ok(full.chars().take(12).collect())
}

fn combine_yara_files(repo_root: &Path, out_path: &Path) -> Result<PathBuf> {
    let mut includes = String::new();

    for entry in walkdir::WalkDir::new(repo_root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let p = entry.path();
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext != "yar" && ext != "yara" {
            continue;
        }

        let inc_path = p.to_string_lossy().replace('\\', "\\\\");
        includes.push_str(&format!("include \"{}\"\n", inc_path));
    }

    fs::write(out_path, includes)
        .with_context(|| format!("Failed writing {}", out_path.display()))?;
    Ok(out_path.to_path_buf())
}
