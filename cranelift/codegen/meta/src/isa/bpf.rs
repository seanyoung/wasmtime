use crate::cdsl::isa::TargetIsa;
use crate::cdsl::settings::SettingGroupBuilder;

pub(crate) fn define() -> TargetIsa {
    let settings = SettingGroupBuilder::new("bpf");

    TargetIsa::new("bpf", settings.build())
}
