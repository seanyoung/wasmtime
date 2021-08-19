pub mod emit;
pub mod regs;

#[repr(u8)]
pub enum Class {
    Ld = 0,
    Ldx = 1,
    St = 2,
    Stx = 3,
    Alu = 4,
    Jmp = 5,
    Jmp32 = 6,
    Alu64 = 7,
}

#[repr(u8)]
pub enum AluUniOp {
    Neg = 0x80,
    End = 0xd0,
}

#[repr(u8)]
pub enum AluBinOp {
    Add = 0x00,
    Sub = 0x10,
    Mul = 0x20,
    Div = 0x30,
    Or = 0x40,
    And = 0x50,
    Lsh = 0x60,
    Rsh = 0x70,
    Mod = 0x90,
    Xor = 0xa0,
    Mov = 0xb0,
    Arsh = 0xc0,
}

#[repr(u8)]
pub enum JmpOp {
    Jeq = 0x10,
    Jgt = 0x20,
    Jge = 0x30,
    Jset = 0x40,
    Jne = 0x50,
    Jsgt = 0x60,
    Jsge = 0x70,
    Call = 0x80,
    Exit = 0x90,
    Jlt = 0xa0,
    Jle = 0xb0,
    Jslt = 0xc0,
    Jsle = 0xd0,
    TailCall = 0xf0,
}

#[repr(u8)]
pub enum Source {
    Reg = 0x00,
    Imm = 0x08,
}

#[repr(u8)]
pub enum Size {
    B = 0x00,
    H = 0x08,
    W = 0x10,
    DW = 0x18,
}

#[repr(u8)]
pub enum Mode {
    Imm = 0x00,
    Abs = 0x20,
    Ind = 0x40,
    Mem = 0x60,
    Atomic = 0xc0,
}

pub struct Reg {
    bits: u32,
}

/// Instruction formats.
#[derive(Clone, Debug)]
pub enum Inst {
    StoreImm {
        dst: Reg,
        offset: i16,
        size: Size,
        imm: i16,
    },
    StoreReg {
        dst: Reg,
        offset: i16,
        size: Size,
        src: Reg,
    },
    Load {
        dst: Reg,
        offset: i16,
        size: Size,
        src: Reg,
    },
    MovImm {
        dst: Reg,
        imm: i64,
    },
    Unary {
        op: AluUniOp,
        dst: Reg,
        bits64: bool,
    },
    BinaryImm {
        op: AluBinOp,
        dst: Reg,
        imm: i32,
        bits64: bool,
    },
    BinaryReg {
        op: AluBinOp,
        src: Reg,
        dst: Reg,
        bits64: bool,
    },
    Call {
        tail_call: bool,
        imm: i32,
    },
    Exit,
    JmpReg {
        cond: JmpOp,
        src: Reg,
        dst: Reg,
        bits64: bool,
        offset: i16,
    },
    JmpImm {
        cond: JmpOp,
        src: Reg,
        imm: i32,
        offset: i16,
    },
}
