//! This module defines aarch64-specific machine instruction types.

use crate::binemit::{Addend, CodeOffset, Reloc};
use crate::ir::types::{F32, F64, I128, I16, I32, I64, I8, I8X16, R32, R64};
use crate::ir::{types, ExternalName, MemFlags, Opcode, Type};
use crate::isa::bpf::BPFABIMachineSpec;
use crate::isa::{CallConv, FunctionAlignment};
use crate::machinst::*;
use crate::machinst::{PrettyPrint, Reg, RegClass, Writable};
use crate::{settings, CodegenError, CodegenResult};

use alloc::vec::Vec;
use regalloc2::{PRegSet, VReg};
use smallvec::{smallvec, SmallVec};
use std::fmt::Write;
use std::string::{String, ToString};

use crate::isa::bpf::lower::isle::generated_code::AluOpcode;
pub use crate::isa::bpf::lower::isle::generated_code::MInst as Inst;

pub mod emit;
pub(crate) mod regs;
pub use self::emit::*;
pub(crate) use self::regs::*;

impl MachInst for Inst {
    type LabelUse = LabelUse;
    type ABIMachineSpec = BPFABIMachineSpec;

    // TODO
    const TRAP_OPCODE: &'static [u8] = &[0; 8];

    fn gen_dummy_use(reg: Reg) -> Self {
        Inst::DummyUse { reg }
    }

    fn canonical_type_for_rc(rc: RegClass) -> Type {
        match rc {
            regalloc2::RegClass::Int => I64,
            regalloc2::RegClass::Float => F64,
            regalloc2::RegClass::Vector => I8X16,
        }
    }

    fn is_safepoint(&self) -> bool {
        match self {
            &Inst::Call { .. } => true,
            _ => false,
        }
    }

    fn get_operands<F: Fn(VReg) -> VReg>(&self, collector: &mut OperandCollector<'_, F>) {
        bpf_get_operands(self, collector);
    }

    fn is_move(&self) -> Option<(Writable<Reg>, Reg)> {
        match self {
            Inst::AluRR { rd, rs, op, .. } if *op == AluOpcode::Mov => {
                Some((rd.clone(), rs.clone()))
            }
            _ => None,
        }
    }

    fn is_included_in_clobbers(&self) -> bool {
        match self {
            &Inst::Args { .. } => false,
            _ => true,
        }
    }

    fn is_trap(&self) -> bool {
        false
    }

    fn is_args(&self) -> bool {
        match self {
            Self::Args { .. } => true,
            _ => false,
        }
    }

    fn is_term(&self) -> MachTerminator {
        match self {
            &Inst::Jmp { .. } => MachTerminator::Uncond,
            &Inst::JmpCondRI { .. } => MachTerminator::Cond,
            &Inst::JmpCondRI32 { .. } => MachTerminator::Cond,
            &Inst::JmpCondRR { .. } => MachTerminator::Cond,
            &Inst::JmpCondRR32 { .. } => MachTerminator::Cond,
            &Inst::Exit { .. } => MachTerminator::Ret,
            _ => MachTerminator::None,
        }
    }

    fn is_mem_access(&self) -> bool {
        match self {
            &Inst::LdAbs { .. }
            | &Inst::LdDwImm { .. }
            | &Inst::LdInd { .. }
            | &Inst::StImm { .. }
            | &Inst::StReg { .. } => true,
            _ => false,
        }
    }

    fn gen_move(to_reg: Writable<Reg>, from_reg: Reg, ty: Type) -> Inst {
        Inst::AluRR {
            op: AluOpcode::Mov,
            rd: to_reg,
            rs: from_reg,
        }
    }

    fn gen_nop(preferred_size: usize) -> Inst {
        if preferred_size == 0 {
            return Inst::Nop0;
        }
        // We can't give a NOP (or any insn) < 8 bytes.
        assert!(preferred_size >= 8);
        Inst::Nop8
    }

    fn rc_for_type(ty: Type) -> CodegenResult<(&'static [RegClass], &'static [Type])> {
        match ty {
            I8 => Ok((&[RegClass::Int], &[I8])),
            I16 => Ok((&[RegClass::Int], &[I16])),
            I32 => Ok((&[RegClass::Int], &[I32])),
            I64 => Ok((&[RegClass::Int], &[I64])),
            R32 => panic!("32-bit reftype pointer should never be seen on riscv64"),
            R64 => Ok((&[RegClass::Int], &[R64])),
            F32 => Ok((&[RegClass::Float], &[F32])),
            F64 => Ok((&[RegClass::Float], &[F64])),
            I128 => Ok((&[RegClass::Int, RegClass::Int], &[I64, I64])),
            _ if ty.is_vector() => {
                debug_assert!(ty.bits() <= 512);

                // Here we only need to return a SIMD type with the same size as `ty`.
                // We use these types for spills and reloads, so prefer types with lanes <= 31
                // since that fits in the immediate field of `vsetivli`.
                const SIMD_TYPES: [[Type; 1]; 6] = [
                    [types::I8X2],
                    [types::I8X4],
                    [types::I8X8],
                    [types::I8X16],
                    [types::I16X16],
                    [types::I32X16],
                ];
                let idx = (ty.bytes().ilog2() - 1) as usize;
                let ty = &SIMD_TYPES[idx][..];

                Ok((&[RegClass::Vector], ty))
            }
            _ => Err(CodegenError::Unsupported(format!(
                "Unexpected SSA-value type: {}",
                ty
            ))),
        }
    }

    fn gen_jump(target: MachLabel) -> Inst {
        Inst::Jmp { label: target }
    }

    fn worst_case_size() -> CodeOffset {
        16
    }

    fn ref_type_regclass(_settings: &settings::Flags) -> RegClass {
        RegClass::Int
    }

    fn function_alignment() -> FunctionAlignment {
        FunctionAlignment {
            minimum: 8,
            preferred: 8,
        }
    }
}

fn bpf_get_operands<F: Fn(VReg) -> VReg>(inst: &Inst, collector: &mut OperandCollector<'_, F>) {
    match inst {
        &Inst::AluRR32 { rd, rs, .. } | &Inst::AluRR { rd, rs, .. } => {
            collector.reg_def(rd);
            collector.reg_use(rs);
        }
        &Inst::AluRI32 { rd, .. } | &Inst::AluRI { rd, .. } => {
            collector.reg_def(rd);
        }
        &Inst::MovImm64 { rd, .. } => {
            collector.reg_def(rd);
        }
        &Inst::JmpCondRI { rs, .. } | &Inst::JmpCondRI32 { rs, .. } => {
            collector.reg_use(rs);
        }
        &Inst::JmpCondRR { rs1, rs2, .. } | &Inst::JmpCondRR32 { rs1, rs2, .. } => {
            collector.reg_use(rs1);
            collector.reg_use(rs2);
        }
        &Inst::LdX { dst, index, .. } => {
            collector.reg_def(dst);
            collector.reg_use(index);
        }
        &Inst::LdDwImm { dst, .. } => {
            collector.reg_def(dst);
        }
        &Inst::LdInd { .. } => {
            todo!();
        }
        &Inst::LdAbs { .. } => {
            todo!();
        }
        &Inst::StImm { index, .. } => {
            collector.reg_use(index);
        }
        &Inst::StReg { index, value, .. } => {
            collector.reg_use(index);
            collector.reg_use(value);
        }
        &Inst::Le { rd, .. } | &Inst::Be { rd, .. } => {
            collector.reg_use(rd.to_reg());
            collector.reg_def(rd);
        }
        &Inst::MovSignExtent { rs, rd, .. } | &Inst::MovSignExtent32 { rs, rd, .. } => {
            collector.reg_def(rd);
            collector.reg_use(rs);
        }
    }
}

/// Different forms of label references for different instruction formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelUse {
    /// 16-bit branch offset for conditional and unconditional jump
    /// instructions.
    Rel16,

    /// 32-bit absolute address used by call
    Call32,
}

impl MachInstLabelUse for LabelUse {
    /// Alignment for veneer code. Every bpf instruction must be
    /// 8-byte-aligned.
    const ALIGN: CodeOffset = 8;

    /// Maximum PC-relative range (positive), inclusive.
    fn max_pos_range(self) -> CodeOffset {
        match self {
            LabelUse::Call32 => u32::MAX,
            LabelUse::Rel16 => i16::MAX as u32 * 8,
        }
    }

    /// Maximum PC-relative range (negative).
    fn max_neg_range(self) -> CodeOffset {
        match self {
            LabelUse::Call32 => u32::MAX,
            LabelUse::Rel16 => i16::MIN.abs() as u32 * 8,
        }
    }

    /// Size of window into code needed to do the patch.
    fn patch_size(self) -> CodeOffset {
        match self {
            LabelUse::Rel16 => 2,
            LabelUse::Call32 => 4,
        }
    }

    /// Perform the patch.
    fn patch(self, buffer: &mut [u8], use_offset: CodeOffset, label_offset: CodeOffset) {
        assert!(use_offset % 8 == 0);
        assert!(label_offset % 8 == 0);
        let offset = (label_offset as i64) - (use_offset as i64);

        // re-check range
        assert!(
            offset >= -(self.max_neg_range() as i64) && offset <= (self.max_pos_range() as i64),
            "{:?} offset '{}' use_offset:'{}' label_offset:'{}'  must not exceed max range.",
            self,
            offset,
            use_offset,
            label_offset,
        );
        self.patch_raw_offset(buffer, offset);
    }

    /// Is a veneer supported for this label reference type?
    fn supports_veneer(self) -> bool {
        // no support for veneers
        false
    }

    /// How large is the veneer, if supported?
    fn veneer_size(self) -> CodeOffset {
        unreachable!()
    }

    fn worst_case_veneer_size() -> CodeOffset {
        8
    }

    /// Generate a veneer into the buffer, given that this veneer is at `veneer_offset`, and return
    /// an offset and label-use for the veneer's use of the original label.
    fn generate_veneer(
        self,
        buffer: &mut [u8],
        veneer_offset: CodeOffset,
    ) -> (CodeOffset, LabelUse) {
        unreachable!();
    }

    fn from_reloc(reloc: Reloc, addend: Addend) -> Option<LabelUse> {
        None
    }
}

impl LabelUse {
    #[allow(dead_code)] // in case it's needed in the future
    fn offset_in_range(self, offset: i64) -> bool {
        let min = -(self.max_neg_range() as i64);
        let max = self.max_pos_range() as i64;
        offset >= min && offset <= max
    }

    fn patch_raw_offset(self, buffer: &mut [u8], offset: i64) {
        match self {
            LabelUse::Rel16 => {
                let offset = offset as i16;
                buffer[2..3].clone_from_slice(&offset.to_le_bytes());
            }
            LabelUse::Call32 => {
                unreachable!();
            }
        }
    }
}
