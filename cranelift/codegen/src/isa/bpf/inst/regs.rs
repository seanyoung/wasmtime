//! Riscv64 ISA definitions: registers.
//!

use crate::machinst::{Reg, Writable};

use crate::machinst::RealReg;
use alloc::vec;
use alloc::vec::Vec;

use regalloc2::VReg;
use regalloc2::{PReg, RegClass};

/// Get a reference to the frame pointer (x8).
#[inline]
pub fn fp_reg() -> Reg {
    x_reg(10)
}

/// Get a reference to the first temporary, sometimes "spill temporary",
/// register. This register is used in various ways as a temporary.
#[inline]
pub fn spilltmp_reg() -> Reg {
    x_reg(31)
}

/// Get a writable reference to the spilltmp reg.
#[inline]
pub fn writable_spilltmp_reg() -> Writable<Reg> {
    Writable::from_reg(spilltmp_reg())
}

///spilltmp2
#[inline]
pub fn spilltmp_reg2() -> Reg {
    x_reg(30)
}

/// Get a writable reference to the spilltmp2 reg.
#[inline]
pub fn writable_spilltmp_reg2() -> Writable<Reg> {
    Writable::from_reg(spilltmp_reg2())
}

#[inline]
pub fn x_reg(enc: usize) -> Reg {
    let p_reg = PReg::new(enc, RegClass::Int);
    let v_reg = VReg::new(p_reg.index(), p_reg.class());
    Reg::from(v_reg)
}
pub const fn px_reg(enc: usize) -> PReg {
    PReg::new(enc, RegClass::Int)
}

#[inline]
pub(crate) fn real_reg_to_reg(x: RealReg) -> Reg {
    let v_reg = VReg::new(x.hw_enc() as usize, x.class());
    Reg::from(v_reg)
}

#[allow(dead_code)]
pub(crate) fn x_reg_range(start: usize, end: usize) -> Vec<Writable<Reg>> {
    let mut regs = vec![];
    for i in start..=end {
        regs.push(Writable::from_reg(x_reg(i)));
    }
    regs
}
