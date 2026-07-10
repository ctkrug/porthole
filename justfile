default: check

# Run the same checks the blocking CI job runs (no network)
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test

fmt:
    cargo fmt --all

run domain="":
    cargo run -- {{domain}}

# The live TLS integration tests, which reach real hosts on the internet.
# These are #[ignore]d by default so `just check` stays deterministic.
test-live:
    cargo test --test tls_live -- --ignored
