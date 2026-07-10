use clap::Parser;

/// An animated, color-coded certificate-chain tree for your terminal.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Domain to inspect (e.g. example.com). Prompted for if omitted.
    domain: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.domain {
        Some(domain) => println!("Porthole - inspecting {domain}"),
        None => println!("Porthole - pass a domain, e.g. `porthole example.com`"),
    }
}
