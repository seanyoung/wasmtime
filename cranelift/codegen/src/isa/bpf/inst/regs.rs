use crate::settings;

use regalloc::{
    PrettyPrint, RealRegUniverse, Reg, RegClass, RegClassInfo, Writable, NUM_REG_CLASSES,
};

pub fn create_reg_universe() -> RealRegUniverse {
    let mut regs = vec![];
    let mut allocable_by_class = [None; NUM_REG_CLASSES];

    for i in 0..=10 {
        let reg = Reg::new_real(RegClass::I64, i, i).to_real_reg();
        let name = format!("r{}", i);
        regs.push((reg, name));
    }

    allocable_by_class[RegClass::I64.rc_to_usize()] = Some(RegClassInfo {
        first: 0,
        last: regs.len() - 1,
        suggested_scratch: None,
    });

    // Assert sanity: the indices in the register structs must match their
    // actual indices in the array.
    for (i, reg) in regs.iter().enumerate() {
        assert_eq!(i, reg.0.get_index());
    }

    RealRegUniverse {
        regs,
        allocable: 10,
        allocable_by_class,
    }
}
