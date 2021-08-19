use super::{AluBinOp, AluUniOp, Class, Inst, JmpOp, Mode, Size, Source};
use crate::binemit::{CodeOffset, Reloc, StackMap};
use crate::ir::SourceLoc;
use crate::machinst::{
    inst_common, MachBuffer, MachInstEmit, MachInstEmitInfo, MachInstEmitState, MachLabel,
};
use crate::settings;

// Registers are encoded as a single byte
fn encode_regs(dst: u32, src: u32) -> u8 {
    (dst | (src << 4)) as u8
}

/// State carried between emissions of a sequence of instructions.
#[derive(Default, Clone, Debug)]
pub struct EmitState {
    /// Addend to convert nominal-SP offsets to real-SP offsets at the current
    /// program point.
    pub(crate) virtual_sp_offset: i64,
    /// Offset of FP from nominal-SP.
    pub(crate) nominal_sp_to_fp: i64,
    /// Safepoint stack map for upcoming instruction, as provided to `pre_safepoint()`.
    stack_map: Option<StackMap>,
    /// Current source-code location corresponding to instruction to be emitted.
    cur_srcloc: SourceLoc,
}

impl MachInstEmitState<Inst> for EmitState {
    fn new(abi: &dyn ABICallee<I = Inst>) -> Self {
        EmitState {
            virtual_sp_offset: 0,
            nominal_sp_to_fp: abi.frame_size() as i64,
            stack_map: None,
            cur_srcloc: SourceLoc::default(),
        }
    }

    fn pre_safepoint(&mut self, stack_map: StackMap) {
        self.stack_map = Some(stack_map);
    }

    fn pre_sourceloc(&mut self, srcloc: SourceLoc) {
        self.cur_srcloc = srcloc;
    }
}

impl EmitState {
    fn take_stack_map(&mut self) -> Option<StackMap> {
        self.stack_map.take()
    }

    fn clear_post_insn(&mut self) {
        self.stack_map = None;
    }

    fn cur_srcloc(&self) -> SourceLoc {
        self.cur_srcloc
    }
}

/// Constant state used during function compilation.
pub struct EmitInfo(settings::Flags);

impl EmitInfo {
    pub(crate) fn new(flags: settings::Flags) -> Self {
        Self(flags)
    }
}

impl MachInstEmitInfo for EmitInfo {
    fn flags(&self) -> &settings::Flags {
        &self.0
    }
}

impl MachInstEmit for Inst {
    type State = EmitState;
    type Info = EmitInfo;

    fn emit(&self, sink: &mut MachBuffer<Inst>, emit_info: &Self::Info, state: &mut EmitState) {
        match self {
            Inst::StoreImm {
                imm,
                offset,
                size,
                dst,
            } => {
                sink.put1(Class::St | Mode::Mem | *size);
                sink.put1(encode_regs(dst, 0));
                sink.put2(offset);
                sink.put4(imm);
            }
            Inst::StoreReg {
                src,
                offset,
                size,
                dst,
            } => {
                sink.put1(Class::Stx | Mode::Mem | *size);
                sink.put1(encode_regs(dst, src));
                sink.put2(offset);
                sink.put4(0);
            }
            Inst::Load {
                src,
                offset,
                size,
                dst,
            } => {
                sink.put1(Class::Ldx | Mode::Mem | *size);
                sink.put1(encode_regs(dst, src));
                sink.put2(offset);
                sink.put4(0);
            }
            Inst::MovImm { dst, imm } => {
                match (*imm >> 32) as u32 {
                    0 => {
                        // no sign extend needed
                        sink.put1(Class::Alu | Source::Imm | AluBinOp::Mov);
                        sink.put1(encode_regs(dst, 0));
                        sink.put2(0);
                        sink.put4(imm as u32);
                    }
                    u32::MAX => {
                        // sign extend
                        sink.put1(Class::Alu64 | Source::Imm | AluBinOp::Mov);
                        sink.put1(encode_regs(dst, 0));
                        sink.put2(0);
                        sink.put4(imm as u32);
                    }
                    _ => {
                        // opcode
                        sink.put1(Class::Ld | Source::Imm | Size::DW);
                        sink.put1(encode_regs(dst, 0));
                        sink.put2(0);
                        sink.put4(imm as u32);
                        // upper 32 bits in 2nd opcode
                        sink.put4(0);
                        sink.put4((imm >> 32) as u32);
                    }
                }
            }
            Inst::Unary { op, dst, bits64 } => {
                sink.put1(if bits64 {
                    Class::Alu64 | Source::Reg | op
                } else {
                    Class::Alu | Source::Reg | op
                });

                sink.put1(encode_regs(dst, 0));
                sink.put2(0);
                sink.put4(0);
            }
            Inst::BinaryImm {
                op,
                dst,
                imm,
                bits64,
            } => {
                sink.put1(if bits64 {
                    Class::Alu64 | Source::Imm | op
                } else {
                    Class::Alu | Source::Imm | op
                });

                sink.put1(encode_regs(dst, 0));
                sink.put2(0);
                sink.put4(imm);
            }
            Inst::BinaryReg {
                op,
                src,
                dst,
                bits64,
            } => {
                sink.put1(if bits64 {
                    Class::Alu64 | Source::Reg | op
                } else {
                    Class::Alu | Source::Reg | op
                });

                sink.put1(encode_regs(dst, src));
                sink.put2(0);
                sink.put4(0);
            }
            Inst::Call { tail_call, imm } => {
                if tail_call {
                    sink.put_data(&[Class::Jmp | JmpOp::TailCall, 0, 0, 0]);
                } else {
                    sink.put_data(&[Class::Jmp | JmpOp::Call, 0, 0, 0]);
                }

                sink.put4(imm);
            }
            Inst::Exit => {
                sink.put_data(&[Class::Jmp | JmpOp::Exit, 0, 0, 0, 0, 0, 0, 0]);
            }
            Inst::JmpReg {
                cond,
                src,
                dst,
                bits64,
                offset,
            } => {
                sink.put1(if bits64 {
                    Class::Jmp | Source::Reg | cond
                } else {
                    Class::Jmp32 | Source::Reg | cond
                });

                sink.put1(encode_regs(dst, src));
                sink.put2(offset);
                sink.put4(0);
            }
            Inst::JmpImm {
                cond,
                src,
                imm,
                bits64,
                offset,
            } => {
                sink.put1(if bits64 {
                    Class::Jmp | Source::Imm | cond
                } else {
                    Class::Jmp32 | Source::Imm | cond
                });

                sink.put1(encode_regs(0, src));
                sink.put2(offset);
                sink.put4(imm);
            }
        }
    }
}
