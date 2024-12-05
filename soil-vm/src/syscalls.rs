use soil::Reg;

use crate::{Register, Trap};

pub trait SyscallHandler {
    fn handle_syscall(
        &self,
        number: u8,
        registers: &mut [Register; 8],
        memory: &mut [u8],
        ip: &mut usize,
    ) -> Result<(), Trap>;
}

pub struct DefaultSyscalls;

impl SyscallHandler for DefaultSyscalls {
    fn handle_syscall(
        &self,
        number: u8,
        registers: &mut [Register; 8],
        memory: &mut [u8],
        ip: &mut usize,
    ) -> Result<(), Trap> {
        match number {
            0 => std::process::exit(registers[Reg::A as usize].read_int() as i32),
            1 => {
                let start = registers[Reg::A as usize].read_int() as usize;
                let len = registers[Reg::B as usize].read_int() as usize;
                println!("{}", String::from_utf8_lossy(&memory[start..start + len]));
            }
            2 => {
                let start = registers[Reg::A as usize].read_int() as usize;
                let len = registers[Reg::B as usize].read_int() as usize;
                eprintln!("{}", String::from_utf8_lossy(&memory[start..start + len]));
            }
            _ => return Err(Trap::UnknownSyscall(number)),
        }
        Ok(())
    }
}
