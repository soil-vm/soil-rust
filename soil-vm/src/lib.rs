pub mod syscalls;

use std::{collections::HashSet, ops::Neg};

use soil::{Instruction, InstructionKind, Reg, SoilBinary};
use syscalls::{DefaultSyscalls, SyscallHandler};

const VM_MEM_SIZE: usize = 1000000;

pub enum ControlFlow {
    Continue,
    Breakpoint,
    Jump(usize),
}

#[derive(Clone, Debug)]
pub enum Trap {
    Panic(String),
    CallStackEmpty,
    FloatException,
    UnknownSyscall(u8),
    Exited,
    IllegalJump,
    Breakpoint,
}

#[derive(Clone, Copy, Default)]
pub struct Register([u8; 8]);

impl Register {
    pub fn read_int(&self) -> i64 {
        i64::from_le_bytes(self.0)
    }

    pub fn read_float(&self) -> f64 {
        f64::from_le_bytes(self.0)
    }

    pub fn write_int(&mut self, value: i64) {
        self.0.copy_from_slice(&value.to_le_bytes())
    }

    pub fn write_float(&mut self, value: f64) {
        self.0.copy_from_slice(&value.to_le_bytes())
    }
}

pub struct TryFrame {
    sp: i64,
    call_stack_size: usize,
    catch: i64,
}

pub struct Vm<S: SyscallHandler> {
    memory: Vec<u8>,
    registers: [Register; 8],
    ip: usize,
    try_stack: Vec<TryFrame>,
    call_stack: Vec<usize>,
    bytecode: SoilBinary,
    syscalls: S,
    breakpoints: HashSet<usize>,
    dbg_instrs: bool,
}

impl Vm<DefaultSyscalls> {
    pub fn new(bytecode: SoilBinary, dbg_instrs: bool) -> Self {
        Self::with_syscalls(bytecode, DefaultSyscalls, dbg_instrs)
    }
}

impl<S: SyscallHandler> Vm<S> {
    pub fn with_syscalls(bytecode: SoilBinary, syscalls: S, dbg_instrs: bool) -> Self {
        let mut vm = Vm {
            memory: Vec::with_capacity(VM_MEM_SIZE),
            registers: [Register::default(); 8],
            ip: 0,
            try_stack: vec![],
            call_stack: vec![],
            bytecode,
            syscalls,
            breakpoints: HashSet::default(),
            dbg_instrs,
        };
        vm.write_reg(Reg::SP, VM_MEM_SIZE as i64);
        vm
    }

    pub fn ip(&self) -> usize {
        self.ip
    }

    fn read_reg(&self, reg: Reg) -> i64 {
        self.registers[reg as usize].read_int()
    }

    fn readf_reg(&self, reg: Reg) -> f64 {
        self.registers[reg as usize].read_float()
    }

    fn writef_reg(&mut self, reg: Reg, value: f64) {
        self.registers[reg as usize].write_float(value);
    }

    fn write_reg(&mut self, reg: Reg, value: i64) {
        self.registers[reg as usize].write_int(value);
    }

    fn read_mem(&self, addr: i64) -> u8 {
        self.memory[addr as usize]
    }

    fn read_mem_word(&self, addr: i64) -> i64 {
        let addr = addr as usize;
        i64::from_le_bytes(
            self.memory[addr..addr + std::mem::size_of::<i64>()]
                .try_into()
                .unwrap(),
        )
    }

    fn write_mem(&mut self, addr: i64, value: u8) {
        let addr = addr as usize;
        self.memory[addr] = value;
    }

    fn write_mem_word(&mut self, addr: i64, value: i64) {
        let addr = addr as usize;
        self.memory[addr..addr + std::mem::size_of::<i64>()].copy_from_slice(&value.to_le_bytes())
    }

    pub fn format_status(&self) -> String {
        let mut s = format!("IP = {:02};\t", self.ip);
        for reg in soil::REGS {
            s = format!("{s}{reg:?} = {};\t", self.read_reg(reg));
        }
        s
    }

    fn print_registers(&self) {
        print!("IP = {:02};\t", self.ip);
        for reg in soil::REGS {
            print!("{reg:?} = {};\t", self.read_reg(reg));
        }
        println!();
    }

    pub fn run(&mut self) -> Result<(), Trap> {
        let bytecode = self
            .bytecode
            .bytecode()
            .ok_or(Trap::Panic("Invalid binary".to_string()))?
            .to_vec();
        while self.ip < bytecode.len() {
            if self.dbg_instrs {
                print!("{:x};\t", bytecode[self.ip].opcode());
            }
            let res = self.run_instruction(bytecode[self.ip])?;
            match res {
                ControlFlow::Continue => self.ip += 1,
                ControlFlow::Jump(target) => self.ip = target,
                ControlFlow::Breakpoint => {}
            }
            if self.dbg_instrs {
                self.print_registers();
            }
        }
        Ok(())
    }

    fn find_jump_target(&self, target: usize) -> Option<usize> {
        self.bytecode
            .bytecode()?
            .iter()
            .enumerate()
            .find_map(|(idx, i)| {
                if i.location == target {
                    Some(idx)
                } else {
                    None
                }
            })
    }

    pub fn set_breakpoint(&mut self, target: usize) {
        self.breakpoints.insert(target);
    }

    pub fn unset_breakpoint(&mut self, target: usize) {
        self.breakpoints.remove(&target);
    }

    pub fn step(&mut self) -> Result<(), Trap> {
        let bytecode = self
            .bytecode
            .bytecode()
            .ok_or(Trap::Panic("Invalid binary".to_string()))?;
        if self.ip >= bytecode.len() {
            return Err(Trap::Panic("Reached end of bytecode".to_string()));
        }
        let res = self.run_instruction(bytecode[self.ip])?;

        match res {
            ControlFlow::Continue => self.ip += 1,
            ControlFlow::Breakpoint => {
                self.ip += 1;
                return Err(Trap::Breakpoint);
            }
            ControlFlow::Jump(target) => self.ip = target,
        }
        Ok(())
    }

    fn run_instruction(&mut self, instr: Instruction) -> Result<ControlFlow, Trap> {
        if self.breakpoints.contains(&instr.location) {
            return Ok(ControlFlow::Breakpoint);
        }
        match instr.kind {
            InstructionKind::Nop => {}
            InstructionKind::Panic => match self.try_stack.pop() {
                Some(frame) => {
                    self.write_reg(Reg::SP, frame.sp);
                    self.call_stack.truncate(frame.call_stack_size);
                    return Ok(ControlFlow::Jump(frame.catch as usize));
                }
                None => return Err(Trap::Panic("VM panicked".to_string())),
            },
            InstructionKind::TryStart(catch) => self.try_stack.push(TryFrame {
                sp: self.read_reg(Reg::SP),
                call_stack_size: self.call_stack.len(),
                catch,
            }),
            InstructionKind::TryEnd => {
                self.try_stack.pop();
            }
            InstructionKind::Move(r1, r2) => {
                self.write_reg(r1, self.read_reg(r2));
            }
            InstructionKind::Movei(r, w) => {
                self.write_reg(r, w);
            }
            InstructionKind::Moveib(r, b) => {
                self.write_reg(r, b as i64);
            }
            InstructionKind::Load(r1, r2) => {
                self.write_reg(r1, self.read_mem_word(self.read_reg(r2)));
            }
            InstructionKind::Loadb(r1, r2) => {
                self.write_reg(r1, self.read_mem(self.read_reg(r2)).into());
            }
            InstructionKind::Store(r1, r2) => {
                self.write_mem_word(self.read_reg(r1), self.read_mem_word(self.read_reg(r2)));
            }
            InstructionKind::Storeb(r1, r2) => {
                self.write_mem(self.read_reg(r1), self.read_mem(self.read_reg(r2)));
            }
            InstructionKind::Push(r) => {
                self.write_reg(Reg::SP, self.read_reg(Reg::SP) - 8);
                self.write_mem_word(self.read_reg(Reg::SP), self.read_mem_word(self.read_reg(r)));
            }
            InstructionKind::Pop(r) => {
                self.write_reg(r, self.read_mem_word(self.read_reg(r)));
                self.write_reg(Reg::SP, self.read_reg(Reg::SP) + 8);
            }
            InstructionKind::Jump(target) => {
                return Ok(ControlFlow::Jump(
                    self.find_jump_target(target).ok_or(Trap::IllegalJump)?,
                ));
            }
            InstructionKind::Cjump(target) => {
                if self.read_reg(Reg::ST) != 0 {
                    return Ok(ControlFlow::Jump(
                        self.find_jump_target(target).ok_or(Trap::IllegalJump)?,
                    ));
                }
            }
            InstructionKind::Call(target) => {
                self.call_stack.push(self.ip);
                return Ok(ControlFlow::Jump(
                    self.find_jump_target(target).ok_or(Trap::IllegalJump)?,
                ));
            }
            InstructionKind::Ret => match self.call_stack.pop() {
                Some(target) => self.ip = target,
                None => return Err(Trap::CallStackEmpty),
            },
            InstructionKind::Syscall(num) => {
                self.syscalls.handle_syscall(
                    num,
                    &mut self.registers,
                    &mut self.memory,
                    &mut self.ip,
                )?;
            }
            InstructionKind::Cmp(r1, r2) => {
                self.write_reg(Reg::ST, self.read_reg(r1) - self.read_reg(r2));
            }
            InstructionKind::Isequal => {
                if self.read_reg(Reg::ST) == 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Isless => {
                if self.read_reg(Reg::ST) < 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Isgreater => {
                if self.read_reg(Reg::ST) > 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Islessequal => {
                if self.read_reg(Reg::ST) <= 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Isgreaterequal => {
                if self.read_reg(Reg::ST) >= 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Isnotequal => {
                if self.read_reg(Reg::ST) != 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fcmp(r1, r2) => {
                self.writef_reg(Reg::ST, self.readf_reg(r1) - self.readf_reg(r2))
            }
            InstructionKind::Fisequal => {
                if self.readf_reg(Reg::ST) == 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fisless => {
                if self.readf_reg(Reg::ST) < 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fisgreater => {
                if self.readf_reg(Reg::ST) > 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fislessequal => {
                if self.readf_reg(Reg::ST) <= 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fisgreaterequal => {
                if self.readf_reg(Reg::ST) >= 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::Fisnotequal => {
                if self.readf_reg(Reg::ST) != 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            InstructionKind::IntToFloat(r) => {
                self.writef_reg(r, self.read_reg(r) as f64);
            }
            InstructionKind::FloatToInt(r) => {
                self.write_reg(r, self.readf_reg(r) as i64);
            }
            InstructionKind::Add(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) + self.read_reg(r2));
            }
            InstructionKind::Sub(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) - self.read_reg(r2));
            }
            InstructionKind::Mul(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) * self.read_reg(r2));
            }
            InstructionKind::Div(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) / self.read_reg(r2));
            }
            InstructionKind::Rem(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) % self.read_reg(r2));
            }
            InstructionKind::Fadd(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) + self.readf_reg(r2));
            }
            InstructionKind::Fsub(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) - self.readf_reg(r2));
            }
            InstructionKind::Fmul(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) * self.readf_reg(r2));
            }
            InstructionKind::Fdiv(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) / self.readf_reg(r2));
            }
            InstructionKind::And(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) & self.read_reg(r2));
            }
            InstructionKind::Or(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) | self.read_reg(r2));
            }
            InstructionKind::Xor(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) ^ self.read_reg(r2));
            }
            InstructionKind::Negate(r) => self.write_reg(r, self.read_reg(r).neg()),
        }
        Ok(ControlFlow::Continue)
    }
}
