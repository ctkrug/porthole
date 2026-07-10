use std::process::Command;

#[test]
fn help_flag_prints_usage_and_exits_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .arg("--help")
        .output()
        .expect("failed to run porthole --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage"));
    assert!(stdout.contains("DOMAIN"));
}

#[test]
fn unknown_flag_is_a_clean_usage_error_not_a_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .arg("--bogus-flag")
        .output()
        .expect("failed to run porthole --bogus-flag");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn extra_positional_argument_is_a_clean_usage_error_not_a_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(["example.com", "unexpected-second-arg"])
        .output()
        .expect("failed to run porthole with two positional args");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn version_flag_prints_a_version_and_exits_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .arg("--version")
        .output()
        .expect("failed to run porthole --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("porthole"));
}
