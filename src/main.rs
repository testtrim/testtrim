use testtrim::{process_command, Cli};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    process_command(cli);
}
