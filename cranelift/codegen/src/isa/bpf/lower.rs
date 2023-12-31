//! Lowering rules for BPF
use crate::ir::Inst as IRInst;
use crate::isa::bpf::inst::*;
use crate::isa::bpf::BPFBackend;
use crate::machinst::lower::*;
use crate::machinst::*;
pub mod isle;

//=============================================================================
// Lowering-backend trait implementation.

impl LowerBackend for BPFBackend {
    type MInst = Inst;

    fn lower(&self, ctx: &mut Lower<Inst>, ir_inst: IRInst) -> Option<InstOutput> {
        None //isle::lower(ctx, self, ir_inst)
    }

    fn lower_branch(
        &self,
        ctx: &mut Lower<Inst>,
        ir_inst: IRInst,
        targets: &[MachLabel],
    ) -> Option<()> {
        None // isle::lower_branch(ctx, self, ir_inst, targets)
    }

    fn maybe_pinned_reg(&self) -> Option<Reg> {
        // pinned register is a register that you want put anything in it.
        // right now riscv64 not support this feature.
        None
    }

    type FactFlowState = ();
}
