//! BPF ISA: binary code emission.

use crate::binemit::StackMap;
use crate::ir::{self, LibCall, RelSourceLoc, TrapCode};
use crate::isa::bpf::inst::*;
use crate::machinst::{AllocationConsumer, Reg, Writable};
use crate::trace;
use cranelift_control::ControlPlane;
use regalloc2::Allocation;

pub struct EmitInfo {
    shared_flag: settings::Flags,
}

impl EmitInfo {
    pub(crate) fn new(shared_flag: settings::Flags) -> Self {
        Self { shared_flag }
    }
}

impl MachInstEmit for Inst {
    type State = EmitState;
    type Info = EmitInfo;

    fn emit(
        &self,
        allocs: &[Allocation],
        sink: &mut MachBuffer<Inst>,
        emit_info: &Self::Info,
        state: &mut EmitState,
    ) {
        // Transform this into a instruction with all the physical regs
        let mut allocs = AllocationConsumer::new(allocs);
        let inst = self.clone().allocate(&mut allocs);

        // Check if we need to update the vector state before emitting this instruction
        if let Some(expected) = inst.expected_vstate() {
            if state.vstate != EmitVState::Known(expected.clone()) {
                // Update the vector state.
                Inst::VecSetState {
                    rd: writable_zero_reg(),
                    vstate: expected.clone(),
                }
                .emit(&[], sink, emit_info, state);
            }
        }

        // N.B.: we *must* not exceed the "worst-case size" used to compute
        // where to insert islands, except when islands are explicitly triggered
        // (with an `EmitIsland`). We check this in debug builds. This is `mut`
        // to allow disabling the check for `JTSequence`, which is always
        // emitted following an `EmitIsland`.
        let mut start_off = sink.cur_offset();

        // First try to emit this as a compressed instruction
        let res = inst.try_emit_compressed(sink, emit_info, state, &mut start_off);
        if res.is_none() {
            // If we can't lets emit it as a normal instruction
            inst.emit_uncompressed(sink, emit_info, state, &mut start_off);
        }

        let end_off = sink.cur_offset();
        assert!(
            (end_off - start_off) <= Inst::worst_case_size(),
            "Inst:{:?} length:{} worst_case_size:{}",
            self,
            end_off - start_off,
            Inst::worst_case_size()
        );
    }

    fn pretty_print_inst(&self, allocs: &[Allocation], state: &mut Self::State) -> String {
        let mut allocs = AllocationConsumer::new(allocs);
        self.print_with_state(state, &mut allocs)
    }
}
