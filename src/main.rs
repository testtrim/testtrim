use clap::Parser;
use testtrim::{process_command, Cli};

fn main() {
    let cli = Cli::parse();
    process_command(cli);
}
