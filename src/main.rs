use rust_coverage_thingy::{process_command, Cli};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    process_command(cli);
}
