//! Integration-style checks for mac seatbelt (run on macOS).

use std::path::Path;
use std::process::Command;

use sandbox_mech_mac::generate_seatbelt_profile;
use sandbox_policy::SandboxPolicy;

#[test]
fn seatbelt_blocks_path_outside_workdir() {
    if !cfg!(target_os = "macos") {
        return;
    }
    if !Path::new("/usr/bin/sandbox-exec").exists() {
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("ws");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("ok.txt"), b"ok").unwrap();

    // Secret file outside workdir
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"leak").unwrap();

    let policy = SandboxPolicy::default();
    let profile = generate_seatbelt_profile(&policy, &work).unwrap();
    let profile_path = tmp.path().join("p.sb");
    std::fs::write(&profile_path, profile).unwrap();

    // Reading inside workdir should succeed
    let ok = Command::new("/usr/bin/sandbox-exec")
        .args([
            "-f",
            profile_path.to_str().unwrap(),
            "/bin/cat",
            work.join("ok.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "workdir read failed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&ok.stdout), "ok");

    // Reading outside should fail under deny-default seatbelt
    let denied = Command::new("/usr/bin/sandbox-exec")
        .args([
            "-f",
            profile_path.to_str().unwrap(),
            "/bin/cat",
            secret.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "expected deny for {}, got success with {}",
        secret.display(),
        String::from_utf8_lossy(&denied.stdout)
    );
}
