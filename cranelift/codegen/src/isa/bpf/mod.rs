//! BPF Instruction Set Architecture.

pub use self::inst::{EmitInfo, EmitState, Inst};

use super::{OwnedTargetIsa, TargetIsa};
use crate::dominator_tree::DominatorTree;
use crate::ir::{types, Function, Type};
#[cfg(feature = "unwind")]
use crate::isa::unwind::systemv;
use crate::isa::x64::settings as x64_settings;
use crate::isa::{Builder as IsaBuilder, FunctionAlignment};
use crate::machinst::{
    compile, CompiledCode, CompiledCodeStencil, MachInst, MachTextSectionBuilder, Reg, SigSet,
    TextSectionBuilder, VCode,
};
use crate::result::CodegenResult;
use crate::settings::{self as shared_settings, Flags};
use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use cranelift_control::ControlPlane;
use target_lexicon::Triple;

pub(crate) mod inst;
mod lower;

/// An BPF backend.
pub(crate) struct BPFBackend {
    triple: Triple,
    flags: Flags,
    x64_flags: x64_settings::Flags,
}

impl BPFBackend {
    /// Create a new BPF backend with the given (shared) flags.
    fn new_with_flags(triple: Triple, flags: Flags, x64_flags: x64_settings::Flags) -> Self {
        Self {
            triple,
            flags,
            x64_flags,
        }
    }

    fn compile_vcode(
        &self,
        func: &Function,
        domtree: &DominatorTree,
        ctrl_plane: &mut ControlPlane,
    ) -> CodegenResult<(VCode<inst::Inst>, regalloc2::Output)> {
        // This performs lowering to VCode, register-allocates the code, computes
        // block layout and finalizes branches. The result is ready for binary emission.
        let emit_info = EmitInfo::new(self.flags.clone(), self.x64_flags.clone());
        let sigs = SigSet::new::<abi::BPFABIMachineSpec>(func, &self.flags)?;
        let abi = abi::BPFCallee::new(func, self, &self.x64_flags, &sigs)?;
        compile::compile::<Self>(func, domtree, self, abi, emit_info, sigs, ctrl_plane)
    }
}

impl TargetIsa for BPFBackend {
    fn compile_function(
        &self,
        func: &Function,
        domtree: &DominatorTree,
        want_disasm: bool,
        ctrl_plane: &mut ControlPlane,
    ) -> CodegenResult<CompiledCodeStencil> {
        let (vcode, regalloc_result) = self.compile_vcode(func, domtree, ctrl_plane)?;

        let emit_result = vcode.emit(&regalloc_result, want_disasm, &self.flags, ctrl_plane);
        let frame_size = emit_result.frame_size;
        let value_labels_ranges = emit_result.value_labels_ranges;
        let buffer = emit_result.buffer;
        let sized_stackslot_offsets = emit_result.sized_stackslot_offsets;
        let dynamic_stackslot_offsets = emit_result.dynamic_stackslot_offsets;

        if let Some(disasm) = emit_result.disasm.as_ref() {
            crate::trace!("disassembly:\n{}", disasm);
        }

        Ok(CompiledCodeStencil {
            buffer,
            frame_size,
            vcode: emit_result.disasm,
            value_labels_ranges,
            sized_stackslot_offsets,
            dynamic_stackslot_offsets,
            bb_starts: emit_result.bb_offsets,
            bb_edges: emit_result.bb_edges,
        })
    }

    fn flags(&self) -> &Flags {
        &self.flags
    }

    fn isa_flags(&self) -> Vec<shared_settings::Value> {
        self.x64_flags.iter().collect()
    }

    fn dynamic_vector_bytes(&self, _dyn_ty: Type) -> u32 {
        16
    }

    fn name(&self) -> &'static str {
        "bpf"
    }

    fn triple(&self) -> &Triple {
        &self.triple
    }

    fn text_section_builder(&self, num_funcs: usize) -> Box<dyn TextSectionBuilder> {
        Box::new(MachTextSectionBuilder::<inst::Inst>::new(num_funcs))
    }

    fn function_alignment(&self) -> FunctionAlignment {
        Inst::function_alignment()
    }

    #[cfg(feature = "disas")]
    fn to_capstone(&self) -> Result<capstone::Capstone, capstone::Error> {
        use capstone::prelude::*;
        Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .build()
    }

    fn has_native_fma(&self) -> bool {
        self.x64_flags.use_fma()
    }

    fn has_x86_blendv_lowering(&self, ty: Type) -> bool {
        // The `blendvpd`, `blendvps`, and `pblendvb` instructions are all only
        // available from SSE 4.1 and onwards. Otherwise the i16x8 type has no
        // equivalent instruction which only looks at the top bit for a select
        // operation, so that always returns `false`
        self.x64_flags.use_sse41() && ty != types::I16X8
    }

    fn has_x86_pshufb_lowering(&self) -> bool {
        self.x64_flags.use_ssse3()
    }

    fn has_x86_pmulhrsw_lowering(&self) -> bool {
        self.x64_flags.use_ssse3()
    }

    fn has_x86_pmaddubsw_lowering(&self) -> bool {
        self.x64_flags.use_ssse3()
    }
}

impl fmt::Display for BPFBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MachBackend")
            .field("name", &self.name())
            .field("triple", &self.triple())
            .field("flags", &format!("{}", self.flags()))
            .finish()
    }
}

/// Create a new `isa::Builder`.
pub(crate) fn isa_builder(triple: Triple) -> IsaBuilder {
    IsaBuilder {
        triple,
        setup: x64_settings::builder(),
        constructor: isa_constructor,
    }
}

fn isa_constructor(
    triple: Triple,
    shared_flags: Flags,
    builder: &shared_settings::Builder,
) -> CodegenResult<OwnedTargetIsa> {
    let isa_flags = x64_settings::Flags::new(&shared_flags, builder);
    let backend = BPFBackend::new_with_flags(triple, shared_flags, isa_flags);
    Ok(backend.wrapped())
}
