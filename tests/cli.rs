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
