//! BPF ISA: binary code emission.

use crate::binemit::StackMap;
use crate::ir::{self, LibCall, RelSourceLoc, TrapCode};
use crate::isa::bpf::{abi::BPFABIMachineSpec, inst::*};
use crate::machinst::{AllocationConsumer, Reg, Writable};
use crate::trace;
use cranelift_control::ControlPlane;
use regalloc2::Allocation;

/// State carried between emissions of a sequence of instructions.
#[derive(Default, Clone, Debug)]
pub struct EmitState {
    pub(crate) initial_sp_offset: i64,
    pub(crate) virtual_sp_offset: i64,
    /// Safepoint stack map for upcoming instruction, as provided to `pre_safepoint()`.
    stack_map: Option<StackMap>,
    /// Current source-code location corresponding to instruction to be emitted.
    cur_srcloc: RelSourceLoc,
    /// Only used during fuzz-testing. Otherwise, it is a zero-sized struct and
    /// optimized away at compiletime. See [cranelift_control].
    ctrl_plane: ControlPlane,
}

impl MachInstEmitState<Inst> for EmitState {
    fn new(abi: &Callee<BPFABIMachineSpec>, ctrl_plane: ControlPlane) -> Self {
        EmitState {
            virtual_sp_offset: 0,
            initial_sp_offset: abi.frame_size() as i64,
            stack_map: None,
            cur_srcloc: Default::default(),
            ctrl_plane,
        }
    }

    fn pre_safepoint(&mut self, stack_map: StackMap) {
        self.stack_map = Some(stack_map);
    }

    fn pre_sourceloc(&mut self, srcloc: RelSourceLoc) {
        self.cur_srcloc = srcloc;
    }

    fn ctrl_plane_mut(&mut self) -> &mut ControlPlane {
        &mut self.ctrl_plane
    }

    fn take_ctrl_plane(self) -> ControlPlane {
        self.ctrl_plane
    }
}

impl EmitState {
    fn take_stack_map(&mut self) -> Option<StackMap> {
        self.stack_map.take()
    }

    fn clear_post_insn(&mut self) {
        self.stack_map = None;
    }

    fn cur_srcloc(&self) -> RelSourceLoc {
        self.cur_srcloc
    }
}

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
