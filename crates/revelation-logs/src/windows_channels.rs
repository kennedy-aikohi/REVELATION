use std::process::Command;


pub fn sysmon_channel_present() -> bool {
    let out = Command::new("wevtutil")
        .args(["el"])
        .output();

    let Ok(out) = out else { return false; };
    if !out.status.success() { return false; }

    let s = String::from_utf8_lossy(&out.stdout).to_lowercase();

    s.contains("microsoft-windows-sysmon/operational")
}
