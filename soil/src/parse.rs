use crate::{Instruction, Label, Reg, Section, SectionKind, SoilBinary};

#[derive(Debug)]
pub enum ParseError {
    BadMagic,
    BadSection(u8),
    BadOpcode(u8),
    BadReg(u8),
}

pub struct Parser {
    bytecode: Vec<u8>,
    cursor: usize,
}

impl Parser {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            cursor: 0,
        }
    }

    fn eat_byte(&mut self) -> u8 {
        self.cursor += 1;
        self.bytecode[self.cursor - 1]
    }

    fn eat_bytes(&mut self, n: usize) -> &[u8] {
        let start = self.cursor;
        self.cursor += n;
        &self.bytecode[start..self.cursor]
    }

    fn eat_word(&mut self) -> i64 {
        let bytes = self.eat_bytes(8);
        i64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn parse_section(&mut self) -> Result<Section, ParseError> {
        let kind = SectionKind::try_from(self.eat_byte())?;
        let len = self.eat_word();

        match kind {
            SectionKind::Bytecode => {
                let mut instrs = vec![];
                let mut instr_offsets = vec![];
                let sec_offset = self.cursor;
                let limit = self.cursor + len as usize;
                while self.cursor < limit {
                    let offset = self.cursor - sec_offset;
                    instrs.push(self.parse_instr()?);
                    instr_offsets.push(offset);
                }
                for instr in instrs.iter_mut() {
                    match instr {
                        Instruction::Jump(ref mut target)
                        | Instruction::Cjump(ref mut target)
                        | Instruction::Call(ref mut target) => {
                            let idx = instr_offsets
                                .iter()
                                .enumerate()
                                .find_map(
                                    |(idx, offset)| {
                                        if offset == target {
                                            Some(idx)
                                        } else {
                                            None
                                        }
                                    },
                                )
                                .unwrap();
                            *target = idx;
                        }
                        _ => {}
                    }
                }
                Ok(Section::Bytecode(instrs))
            }
            SectionKind::InitialMemory => {
                let content = self.eat_bytes(len as usize);
                Ok(Section::InitialMemory(content.into()))
            }
            SectionKind::Name => {
                let content = self.eat_bytes(len as usize);
                Ok(Section::Name(String::from_utf8_lossy(content).to_string()))
            }
            SectionKind::Labels => {
                let mut labels = vec![];
                let n_labels = self.eat_word();
                for _ in 0..n_labels {
                    labels.push(self.parse_label());
                }
                Ok(Section::Labels(labels))
            }
            SectionKind::Description => {
                let content = self.eat_bytes(len as usize);
                Ok(Section::Description(
                    String::from_utf8_lossy(content).to_string(),
                ))
            }
        }
    }

    fn parse_label(&mut self) -> Label {
        let position = self.eat_word();
        let len = self.eat_word();
        let label = self.eat_bytes(len as usize);
        Label {
            position: position as usize,
            name: String::from_utf8_lossy(label).to_string(),
        }
    }

    fn parse_reg(&mut self) -> Result<Reg, ParseError> {
        Reg::try_from(self.eat_byte())
    }

    fn parse_two_regs(&mut self) -> Result<(Reg, Reg), ParseError> {
        let regs = self.eat_byte();
        Ok((Reg::try_from(0x0f & regs)?, Reg::try_from(regs >> 4)?))
    }

    fn parse_instr(&mut self) -> Result<Instruction, ParseError> {
        let opcode = self.eat_byte();
        match opcode {
            0x00 => Ok(Instruction::Nop),
            0xe0 => Ok(Instruction::Panic),
            0xe1 => Ok(Instruction::TryStart(self.eat_word())),
            0xe2 => Ok(Instruction::TryEnd),
            0xd0 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Move(r1, r2))
            }
            0xd1 => Ok(Instruction::Movei(self.parse_reg()?, self.eat_word())),
            0xd2 => Ok(Instruction::Moveib(self.parse_reg()?, self.eat_byte())),
            0xd3 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Load(r1, r2))
            }
            0xd4 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Loadb(r1, r2))
            }
            0xd5 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Store(r1, r2))
            }
            0xd6 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Storeb(r1, r2))
            }
            0xd7 => Ok(Instruction::Push(self.parse_reg()?)),
            0xd8 => Ok(Instruction::Pop(self.parse_reg()?)),
            0xf0 => Ok(Instruction::Jump(self.eat_word() as usize)),
            0xf1 => Ok(Instruction::Cjump(self.eat_word() as usize)),
            0xf2 => Ok(Instruction::Call(self.eat_word() as usize)),
            0xf3 => Ok(Instruction::Ret),
            0xf4 => Ok(Instruction::Syscall(self.eat_byte())),
            0xc0 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Cmp(r1, r2))
            }
            0xc1 => Ok(Instruction::Isequal),
            0xc2 => Ok(Instruction::Isless),
            0xc3 => Ok(Instruction::Isgreater),
            0xc4 => Ok(Instruction::Islessequal),
            0xc5 => Ok(Instruction::Isgreaterequal),
            0xc6 => Ok(Instruction::Isnotequal),
            0xc7 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Fcmp(r1, r2))
            }
            0xc8 => Ok(Instruction::Fisequal),
            0xc9 => Ok(Instruction::Fisless),
            0xca => Ok(Instruction::Fisgreater),
            0xcb => Ok(Instruction::Fislessequal),
            0xcc => Ok(Instruction::Fisgreaterequal),
            0xcd => Ok(Instruction::Fisnotequal),
            0xce => Ok(Instruction::IntToFloat(self.parse_reg()?)),
            0xcf => Ok(Instruction::FloatToInt(self.parse_reg()?)),
            0xa0 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Add(r1, r2))
            }
            0xa1 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Sub(r1, r2))
            }
            0xa2 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Mul(r1, r2))
            }
            0xa3 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Div(r1, r2))
            }
            0xa4 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Rem(r1, r2))
            }
            0xa5 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Fadd(r1, r2))
            }
            0xa6 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Fsub(r1, r2))
            }
            0xa7 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Fmul(r1, r2))
            }
            0xa8 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Fdiv(r1, r2))
            }
            0xb0 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::And(r1, r2))
            }
            0xb1 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Or(r1, r2))
            }
            0xb2 => {
                let (r1, r2) = self.parse_two_regs()?;
                Ok(Instruction::Xor(r1, r2))
            }
            0xb3 => Ok(Instruction::Negate(self.parse_reg()?)),
            o => Err(ParseError::BadOpcode(o)),
        }
    }

    pub fn parse(&mut self) -> Result<SoilBinary, ParseError> {
        let magic = self.eat_bytes(4);
        if magic != [0x73, 0x6f, 0x69, 0x6c] {
            return Err(ParseError::BadMagic);
        }
        let mut sections = vec![];
        while self.cursor < self.bytecode.len() {
            sections.push(self.parse_section()?);
        }
        Ok(SoilBinary { sections })
    }
}

pub fn parse(binary: Vec<u8>) -> Result<SoilBinary, ParseError> {
    let mut parser = Parser::new(binary);
    parser.parse()
}