use std::ops::Neg;

use soil::{Instruction, Reg, SoilBinary};

const VM_MEM_SIZE: usize = 1000000;

pub enum ControlFlow {
    Continue,
    Jump(usize),
}

#[derive(Debug)]
pub enum Trap {
    Panic,
    CallStackEmpty,
    FloatException,
    UnknownSyscall(u8),
}

pub struct TryFrame {
    sp: i64,
    call_stack_size: usize,
    catch: i64,
}

pub struct Vm {
    memory: Vec<u8>,
    registers: [[u8; 8]; 8],
    ip: usize,
    try_stack: Vec<TryFrame>,
    call_stack: Vec<usize>,
    bytecode: SoilBinary,
    dbg_instrs: bool,
}

impl Vm {
    pub fn new(bytecode: SoilBinary, dbg_instrs: bool) -> Self {
        let mut vm = Vm {
            memory: Vec::with_capacity(VM_MEM_SIZE),
            registers: [[0; 8]; 8],
            ip: 0,
            try_stack: vec![],
            call_stack: vec![],
            bytecode,
            dbg_instrs,
        };
        vm.write_reg(Reg::SP, VM_MEM_SIZE as i64);
        vm
    }

    fn read_reg(&self, reg: Reg) -> i64 {
        i64::from_le_bytes(self.registers[reg as usize])
    }

    fn readf_reg(&self, reg: Reg) -> f64 {
        f64::from_le_bytes(self.registers[reg as usize])
    }

    fn writef_reg(&mut self, reg: Reg, value: f64) {
        self.registers[reg as usize].copy_from_slice(&value.to_le_bytes())
    }

    fn write_reg(&mut self, reg: Reg, value: i64) {
        self.registers[reg as usize].copy_from_slice(&value.to_le_bytes());
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

    fn handle_syscall(&mut self, nr: u8) -> Result<(), Trap> {
        match nr {
            0 => {
                std::process::exit(self.read_reg(Reg::A) as i32);
            }
            _ => Err(Trap::UnknownSyscall(nr)),
        }
    }

    fn print_registers(&self) {
        print!("IP = {:02};\t", self.ip);
        for reg in soil::REGS {
            print!("{reg:?} = {};\t", self.read_reg(reg));
        }
        println!();
    }

    pub fn run(&mut self) -> Result<(), Trap> {
        let bytecode = self.bytecode.bytecode().ok_or(Trap::Panic)?.to_vec();
        while self.ip < bytecode.len() {
            if self.dbg_instrs {
                print!("{:x};\t", bytecode[self.ip].opcode());
            }
            let res = self.run_instruction(bytecode[self.ip])?;
            match res {
                ControlFlow::Continue => self.ip += 1,
                ControlFlow::Jump(target) => self.ip = target,
            }
            if self.dbg_instrs {
                self.print_registers();
            }
        }
        Ok(())
    }

    fn run_instruction(&mut self, instr: Instruction) -> Result<ControlFlow, Trap> {
        match instr {
            Instruction::Nop => {}
            Instruction::Panic => match self.try_stack.pop() {
                Some(frame) => {
                    self.write_reg(Reg::SP, frame.sp);
                    self.call_stack.truncate(frame.call_stack_size);
                    return Ok(ControlFlow::Jump(frame.catch as usize));
                }
                None => return Err(Trap::Panic),
            },
            Instruction::TryStart(catch) => self.try_stack.push(TryFrame {
                sp: self.read_reg(Reg::SP),
                call_stack_size: self.call_stack.len(),
                catch,
            }),
            Instruction::TryEnd => {
                self.try_stack.pop();
            }
            Instruction::Move(r1, r2) => {
                self.write_reg(r1, self.read_reg(r2));
            }
            Instruction::Movei(r, w) => {
                self.write_reg(r, w);
            }
            Instruction::Moveib(r, b) => {
                self.write_reg(r, b as i64);
            }
            Instruction::Load(r1, r2) => {
                self.write_reg(r1, self.read_mem_word(self.read_reg(r2)));
            }
            Instruction::Loadb(r1, r2) => {
                self.write_reg(r1, self.read_mem(self.read_reg(r2)).into());
            }
            Instruction::Store(r1, r2) => {
                self.write_mem_word(self.read_reg(r1), self.read_mem_word(self.read_reg(r2)));
            }
            Instruction::Storeb(r1, r2) => {
                self.write_mem(self.read_reg(r1), self.read_mem(self.read_reg(r2)));
            }
            Instruction::Push(r) => {
                self.write_reg(Reg::SP, self.read_reg(Reg::SP) - 8);
                self.write_mem_word(self.read_reg(Reg::SP), self.read_mem_word(self.read_reg(r)));
            }
            Instruction::Pop(r) => {
                self.write_reg(r, self.read_mem_word(self.read_reg(r)));
                self.write_reg(Reg::SP, self.read_reg(Reg::SP) + 8);
            }
            Instruction::Jump(target) => return Ok(ControlFlow::Jump(target)),
            Instruction::Cjump(target) => {
                if self.read_reg(Reg::ST) != 0 {
                    return Ok(ControlFlow::Jump(target));
                }
            }
            Instruction::Call(target) => {
                self.call_stack.push(self.ip);
                return Ok(ControlFlow::Jump(target));
            }
            Instruction::Ret => match self.call_stack.pop() {
                Some(target) => self.ip = target,
                None => return Err(Trap::CallStackEmpty),
            },
            Instruction::Syscall(num) => self.handle_syscall(num)?,
            Instruction::Cmp(r1, r2) => {
                self.write_reg(Reg::ST, self.read_reg(r1) - self.read_reg(r2));
            }
            Instruction::Isequal => {
                if self.read_reg(Reg::ST) == 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Isless => {
                if self.read_reg(Reg::ST) < 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Isgreater => {
                if self.read_reg(Reg::ST) > 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Islessequal => {
                if self.read_reg(Reg::ST) <= 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Isgreaterequal => {
                if self.read_reg(Reg::ST) >= 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Isnotequal => {
                if self.read_reg(Reg::ST) != 0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fcmp(r1, r2) => {
                self.writef_reg(Reg::ST, self.readf_reg(r1) - self.readf_reg(r2))
            }
            Instruction::Fisequal => {
                if self.readf_reg(Reg::ST) == 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fisless => {
                if self.readf_reg(Reg::ST) < 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fisgreater => {
                if self.readf_reg(Reg::ST) > 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fislessequal => {
                if self.readf_reg(Reg::ST) <= 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fisgreaterequal => {
                if self.readf_reg(Reg::ST) >= 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::Fisnotequal => {
                if self.readf_reg(Reg::ST) != 0.0 {
                    self.write_reg(Reg::ST, 1);
                } else {
                    self.write_reg(Reg::ST, 0);
                }
            }
            Instruction::IntToFloat(r) => {
                self.writef_reg(r, self.read_reg(r) as f64);
            }
            Instruction::FloatToInt(r) => {
                self.write_reg(r, self.readf_reg(r) as i64);
            }
            Instruction::Add(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) + self.read_reg(r2));
            }
            Instruction::Sub(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) - self.read_reg(r2));
            }
            Instruction::Mul(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) * self.read_reg(r2));
            }
            Instruction::Div(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) / self.read_reg(r2));
            }
            Instruction::Rem(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) % self.read_reg(r2));
            }
            Instruction::Fadd(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) + self.readf_reg(r2));
            }
            Instruction::Fsub(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) - self.readf_reg(r2));
            }
            Instruction::Fmul(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) * self.readf_reg(r2));
            }
            Instruction::Fdiv(r1, r2) => {
                self.writef_reg(r1, self.readf_reg(r1) / self.readf_reg(r2));
            }
            Instruction::And(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) & self.read_reg(r2));
            }
            Instruction::Or(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) | self.read_reg(r2));
            }
            Instruction::Xor(r1, r2) => {
                self.write_reg(r1, self.read_reg(r1) ^ self.read_reg(r2));
            }
            Instruction::Negate(r) => self.write_reg(r, self.read_reg(r).neg()),
        }
        Ok(ControlFlow::Continue)
    }
}
