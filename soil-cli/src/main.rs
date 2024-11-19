use std::path::PathBuf;

use clap::Parser;
use soil_vm::Vm;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the binary to be run
    path: PathBuf,
    /// Prints register states after each instruction
    #[arg(short = 'v')]
    dbg_instrs: bool,
}

fn main() {
    let args = Args::parse();
    let binary = std::fs::read(args.path).unwrap();
    let bytecode = soil::parse::parse(binary).unwrap();
    let mut vm = Vm::new(bytecode, args.dbg_instrs);
    vm.run().unwrap();
}
