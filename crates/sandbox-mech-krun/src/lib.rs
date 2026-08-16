//! libkrun microVM mechanism — stub for v1.
//!
//! Planned: Hypervisor.framework + libkrun Linux arm64 guest with CPU/mem at VM
//! level. Not built yet; see OpenShell `openshell-vm` notes under `vms_v2/refs/`.

use sandbox_core::{
    CreateRequest, CreateResult, DoctorItem, ExecRequest, ExecResult, Mechanism, MechanismError,
};
use sandbox_policy::MechanismKind;

#[derive(Debug, Default)]
pub struct KrunMechanism;

impl KrunMechanism {
    pub fn new() -> Self {
        Self
    }
}

impl Mechanism for KrunMechanism {
    fn kind(&self) -> MechanismKind {
        MechanismKind::Krun
    }

    fn name(&self) -> &'static str {
        "linux_libkrun"
    }

    fn doctor(&self) -> Vec<DoctorItem> {
        vec![
            DoctorItem {
                name: "libkrun".into(),
                ok: false,
                detail: "not built yet — planned Hypervisor.framework Linux arm64 microVM".into(),
            },
            DoctorItem {
                name: "status".into(),
                ok: false,
                detail: "use --mechanism podman (or mac) for now".into(),
            },
        ]
    }

    fn create(&self, _req: &CreateRequest) -> Result<CreateResult, MechanismError> {
        Err(MechanismError::NotImplemented(
            "linux_libkrun is a stub in v1; use podman or mac".into(),
        ))
    }

    fn exec(&self, _req: &ExecRequest) -> Result<ExecResult, MechanismError> {
        Err(MechanismError::NotImplemented(
            "linux_libkrun is a stub in v1".into(),
        ))
    }

    fn remove(&self, _runtime_id: &str) -> Result<(), MechanismError> {
        Err(MechanismError::NotImplemented(
            "linux_libkrun is a stub in v1".into(),
        ))
    }
}
