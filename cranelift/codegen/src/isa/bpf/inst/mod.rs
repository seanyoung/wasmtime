//! This module defines aarch64-specific machine instruction types.

use crate::binemit::{Addend, CodeOffset, Reloc};
use crate::ir::types::{F32, F64, I128, I16, I32, I64, I8, I8X16, R32, R64};
use crate::ir::{types, ExternalName, MemFlags, Opcode, Type};
use crate::isa::{CallConv, FunctionAlignment};
use crate::machinst::*;
use crate::{settings, CodegenError, CodegenResult};

use crate::machinst::{PrettyPrint, Reg, RegClass, Writable};

use alloc::vec::Vec;
use regalloc2::{PRegSet, VReg};
use smallvec::{smallvec, SmallVec};
use std::fmt::Write;
use std::string::{String, ToString};

pub use crate::isa::bpf::lower::isle::generated_code::MInst as Inst;

pub mod emit;
