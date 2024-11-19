use parse::ParseError;

pub mod parse;

#[derive(Debug)]
pub struct SoilBinary {
    sections: Vec<Section>,
}

impl SoilBinary {
    pub fn new(sections: Vec<Section>) -> Self {
        Self { sections }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![b's', b'o', b'i', b'l'];
        for sec in &self.sections {
            bytes.extend_from_slice(&sec.serialize());
        }
        bytes
    }

    pub fn bytecode(&self) -> Option<&[Instruction]> {
        self.sections.iter().find_map(|s| match s {
            Section::Bytecode(b) => Some(b.as_slice()),
            _ => None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Bytecode = 0,
    InitialMemory = 1,
    Name = 2,
    Labels = 3,
    Description = 4,
}

impl TryFrom<u8> for SectionKind {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SectionKind::Bytecode),
            1 => Ok(SectionKind::InitialMemory),
            2 => Ok(SectionKind::Name),
            3 => Ok(SectionKind::Labels),
            4 => Ok(SectionKind::Description),
            s => Err(ParseError::BadSection(s)),
        }
    }
}

#[derive(Debug)]
pub struct Label {
    position: usize,
    name: String,
}

impl Label {
    pub fn new(position: usize, name: String) -> Self {
        Self { position, name }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.position.to_le_bytes());
        bytes.extend_from_slice(&self.name.len().to_le_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Section {
    Bytecode(Vec<Instruction>) = 0,
    InitialMemory(Vec<u8>) = 1,
    Name(String) = 2,
    Labels(Vec<Label>) = 3,
    Description(String) = 4,
}

impl Section {
    pub fn discriminant(&self) -> u8 {
        unsafe { *(self as *const _ as *const u8) }
    }

    pub fn from_instructions(instructions: Vec<Instruction>) -> Self {
        Self::Bytecode(instructions)
    }

    pub fn initial_memory(content: Vec<u8>) -> Self {
        Self::InitialMemory(content)
    }

    pub fn labels(labels: Vec<Label>) -> Self {
        Self::Labels(labels)
    }

    pub fn name<S: ToString>(name: S) -> Section {
        Self::Name(name.to_string())
    }

    pub fn description<S: ToString>(description: S) -> Section {
        Self::Description(description.to_string())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut content = vec![];
        match self {
            Section::Bytecode(bc) => {
                for instr in bc {
                    content.extend_from_slice(&instr.serialize());
                }
            }
            Section::InitialMemory(im) => {
                content.extend_from_slice(&im);
            }
            Section::Name(n) => {
                content.extend_from_slice(&n.as_bytes());
            }
            Section::Labels(l) => {
                content.extend_from_slice(&l.len().to_le_bytes());
                for label in l {
                    content.extend_from_slice(&label.serialize());
                }
            }
            Section::Description(d) => {
                content.extend_from_slice(&d.as_bytes());
            }
        }
        let mut bytes = vec![self.discriminant()];
        bytes.extend_from_slice(&content.len().to_le_bytes());
        bytes.extend_from_slice(&content);
        bytes
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Instruction {
    Nop = 0x00,
    Panic = 0xe0,
    TryStart(i64) = 0xe1,
    TryEnd = 0xe2,
    Move(Reg, Reg) = 0xd0,
    Movei(Reg, i64) = 0xd1,
    Moveib(Reg, u8) = 0xd2,
    Load(Reg, Reg) = 0xd3,
    Loadb(Reg, Reg) = 0xd4,
    Store(Reg, Reg) = 0xd5,
    Storeb(Reg, Reg) = 0xd6,
    Push(Reg) = 0xd7,
    Pop(Reg) = 0xd8,
    Jump(usize) = 0xf0,
    Cjump(usize) = 0xf1,
    Call(usize) = 0xf2,
    Ret = 0xf3,
    Syscall(u8) = 0xf4,
    Cmp(Reg, Reg) = 0xc0,
    Isequal = 0xc1,
    Isless = 0xc2,
    Isgreater = 0xc3,
    Islessequal = 0xc4,
    Isgreaterequal = 0xc5,
    Isnotequal = 0xc6,
    Fcmp(Reg, Reg) = 0xc7,
    Fisequal = 0xc8,
    Fisless = 0xc9,
    Fisgreater = 0xca,
    Fislessequal = 0xcb,
    Fisgreaterequal = 0xcc,
    Fisnotequal = 0xcd,
    IntToFloat(Reg) = 0xce,
    FloatToInt(Reg) = 0xcf,
    Add(Reg, Reg) = 0xa0,
    Sub(Reg, Reg) = 0xa1,
    Mul(Reg, Reg) = 0xa2,
    Div(Reg, Reg) = 0xa3,
    Rem(Reg, Reg) = 0xa4,
    Fadd(Reg, Reg) = 0xa5,
    Fsub(Reg, Reg) = 0xa6,
    Fmul(Reg, Reg) = 0xa7,
    Fdiv(Reg, Reg) = 0xa8,
    And(Reg, Reg) = 0xb0,
    Or(Reg, Reg) = 0xb1,
    Xor(Reg, Reg) = 0xb2,
    Negate(Reg) = 0xb3,
}

impl Instruction {
    pub fn opcode(&self) -> u8 {
        unsafe { *(self as *const _ as *const u8) }
    }

    fn encode_regs(&self, r1: Reg, r2: Reg, bytes: &mut Vec<u8>) {
        bytes.push((r2 as u8) << 4 | (r1 as u8));
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![self.opcode()];
        match self {
            Instruction::Nop
            | Instruction::Panic
            | Instruction::TryEnd
            | Instruction::Ret
            | Instruction::Isequal
            | Instruction::Isless
            | Instruction::Isgreater
            | Instruction::Islessequal
            | Instruction::Isgreaterequal
            | Instruction::Isnotequal
            | Instruction::Fisequal
            | Instruction::Fisless
            | Instruction::Fisgreater
            | Instruction::Fislessequal
            | Instruction::Fisgreaterequal
            | Instruction::Fisnotequal => {}
            Instruction::TryStart(w) => {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            Instruction::Move(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Movei(r, w) => {
                bytes.push(*r as u8);
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            Instruction::Moveib(r, b) => {
                bytes.push(*r as u8);
                bytes.push(*b);
            }
            Instruction::Load(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Loadb(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Store(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Storeb(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Push(r) => {
                bytes.push(*r as u8);
            }
            Instruction::Pop(r) => {
                bytes.push(*r as u8);
            }
            Instruction::Jump(w) => {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            Instruction::Cjump(w) => {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            Instruction::Call(w) => {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            Instruction::Syscall(b) => {
                bytes.push(*b);
            }
            Instruction::Cmp(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Fcmp(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::IntToFloat(r) => {
                bytes.push(*r as u8);
            }
            Instruction::FloatToInt(r) => {
                bytes.push(*r as u8);
            }
            Instruction::Add(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Sub(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Mul(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Div(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Rem(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Fadd(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Fsub(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Fmul(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Fdiv(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::And(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Or(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Xor(r1, r2) => {
                self.encode_regs(*r1, *r2, &mut bytes);
            }
            Instruction::Negate(r) => {
                bytes.push(*r as u8);
            }
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    SP = 0,
    ST = 1,
    A = 2,
    B = 3,
    C = 4,
    D = 5,
    E = 6,
    F = 7,
}

impl TryFrom<u8> for Reg {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Reg::SP),
            1 => Ok(Reg::ST),
            2 => Ok(Reg::A),
            3 => Ok(Reg::B),
            4 => Ok(Reg::C),
            5 => Ok(Reg::D),
            6 => Ok(Reg::E),
            7 => Ok(Reg::F),
            r => Err(ParseError::BadReg(r)),
        }
    }
}

pub const REGS: [Reg; 8] = [
    Reg::SP,
    Reg::ST,
    Reg::A,
    Reg::B,
    Reg::C,
    Reg::D,
    Reg::E,
    Reg::F,
];
