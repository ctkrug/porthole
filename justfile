default: check

# Run the same checks CI runs
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test

fmt:
    cargo fmt --all

run domain="":
    cargo run -- {{domain}}
