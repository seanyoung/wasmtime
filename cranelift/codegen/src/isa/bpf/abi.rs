//! Implementation of the standard bpf ABI.

use crate::ir::{self, types, LibCall, MemFlags, Opcode, Signature, TrapCode, Type};
use crate::ir::{types::*, ExternalName};
use crate::isa;
use crate::isa::{bpf::inst::*, unwind::UnwindInst, CallConv};
use crate::machinst::abi::*;
use crate::machinst::*;
use crate::settings;
use crate::{CodegenError, CodegenResult};
use alloc::boxed::Box;
use alloc::vec::Vec;
use regalloc2::{MachineEnv, PReg, PRegSet, VReg};
use smallvec::{smallvec, SmallVec};
use std::convert::TryFrom;
use std::sync::OnceLock;

/// This is the limit for the size of argument and return-value areas on the
/// stack. We place a reasonable limit here to avoid integer overflow issues
/// with 32-bit arithmetic: for now, 128 MB.
static STACK_ARG_RET_SIZE_LIMIT: u32 = 4 * 1024;

/// Support for the bpf ABI from the callee side (within a function body).
pub(crate) type BPFCallee = Callee<BPFABIMachineSpec>;

/// Support for the bpf ABI from the caller side (at a callsite).
pub(crate) type BPFCallSite = CallSite<BPFABIMachineSpec>;

/// Implementation of ABI primitives for bpf.
pub struct BPFABIMachineSpec;
