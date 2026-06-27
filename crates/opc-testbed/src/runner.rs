//! Scenario runners (local, kind, and hardware-lab).

use crate::evidence::{ScenarioEvidence, ScenarioOutcome};
use crate::scenario::{Scenario, Step};
use crate::simulators::Simulator;
use crate::virtual_time::VirtualClock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Local in-process scenario runner.
pub struct LocalRunner {
    pub clock: VirtualClock,
    pub simulators: BTreeMap<String, Simulator>,
    pub state: HashMap<String, String>,
}

impl LocalRunner {
    pub fn new(clock: VirtualClock) -> Self {
        Self {
            clock,
            simulators: BTreeMap::new(),
            state: HashMap::new(),
        }
    }

    pub fn run(&mut self, scenario: &Scenario) -> Result<ScenarioEvidence, crate::TestbedError> {
        let started_at = *self.clock.now().as_offset_datetime();

        // Initialize simulators from topology
        for (name, spec) in &scenario.topology.nfs {
            if spec.simulator.is_some() {
                self.simulators
                    .insert(name.clone(), Simulator::from_spec(name, spec)?);
            }
        }

        // Execute steps
        let mut failure_summary = None;
        let mut outcome = ScenarioOutcome::Pass;

        for (idx, step) in scenario.steps.iter().enumerate() {
            if let Err(err) = self.execute_step(step) {
                failure_summary = Some(format!("Step {idx} failed: {err}"));
                outcome = ScenarioOutcome::Fail;
                break;
            }
        }

        // Collect all simulator states
        for (name, sim) in &self.simulators {
            for (key, val) in sim.get_all_state() {
                self.state.insert(format!("{name}.{key}"), val);
            }
        }

        // Evaluate assertions if we haven't failed yet
        if outcome == ScenarioOutcome::Pass {
            for assertion in &scenario.assertions {
                match crate::assertions::evaluate(assertion, &self.state) {
                    crate::assertions::AssertionOutcome::Pass => {}
                    crate::assertions::AssertionOutcome::Fail { reason } => {
                        failure_summary =
                            Some(format!("Assertion failed: {} ({})", assertion.expr, reason));
                        outcome = ScenarioOutcome::Fail;
                        break;
                    }
                    crate::assertions::AssertionOutcome::Skipped => {
                        outcome = ScenarioOutcome::Error;
                        failure_summary = Some(format!("Assertion skipped: {}", assertion.expr));
                        break;
                    }
                }
            }
        }

        let finished_at = *self.clock.now().as_offset_datetime();
        let mut evidence = ScenarioEvidence::new(scenario.id.clone(), outcome);
        evidence.requirements = scenario.requirements.clone();
        evidence.mode = Some("in-process".to_string());
        evidence.runner_mode = Some("local".to_string());
        evidence.seed = scenario.seed;
        evidence.started_at = Some(started_at);
        evidence.finished_at = Some(finished_at);
        if let Some(summary) = failure_summary {
            evidence.set_failure_summary(&summary);
        }

        // Expose simulator versions in evidence
        for name in self.simulators.keys() {
            evidence
                .simulator_versions
                .insert(name.clone(), "1.0.0".to_string());
        }

        Ok(evidence)
    }

    fn execute_step(&mut self, step: &Step) -> Result<(), crate::TestbedError> {
        match step {
            Step::ClockJump { duration_ms } => {
                self.clock
                    .advance(time::Duration::milliseconds(*duration_ms as i64));
                Ok(())
            }
            Step::SendNgap { to, message, .. } => {
                let sim = self.simulator_mut(to)?;
                sim.handle_step(step)?;
                self.state
                    .insert(format!("{to}.last_ngap"), message.clone());
                Ok(())
            }
            Step::ExpectSbi {
                from,
                to,
                operation,
            } => {
                if !scenario_endpoint_known(from, &self.simulators) {
                    return Err(crate::TestbedError::Validation(format!(
                        "expect_sbi source '{from}' is not a known simulator"
                    )));
                }
                self.state
                    .insert(format!("{from}.expected_sbi.{to}"), operation.clone());
                Ok(())
            }
            Step::ExpectNgap { from, to, message } => {
                if !scenario_endpoint_known(from, &self.simulators) {
                    return Err(crate::TestbedError::Validation(format!(
                        "expect_ngap source '{from}' is not a known simulator"
                    )));
                }
                self.state
                    .insert(format!("{from}.expected_ngap.{to}"), message.clone());
                Ok(())
            }
            Step::PeerUnavailable { target }
            | Step::DependencyTimeout { target }
            | Step::ProcessRestart { target } => {
                let sim = self.simulator_mut(target)?;
                sim.handle_step(step)
            }
            Step::DelayedResponse { target, delay_ms } => {
                self.simulator_mut(target)?;
                self.clock
                    .advance(time::Duration::milliseconds(*delay_ms as i64));
                self.state.insert(
                    format!("{target}.delayed_response_ms"),
                    delay_ms.to_string(),
                );
                Ok(())
            }
            Step::MalformedResponse { target } => {
                let sim = self.simulator_mut(target)?;
                let result = sim.handle_step(step);
                self.state
                    .insert(format!("{target}.malformed_response"), "true".to_string());
                result
            }
            Step::NetworkPartition { node_a, node_b } => {
                self.simulator_mut(node_a)?;
                self.simulator_mut(node_b)?;
                self.state.insert(
                    format!("{node_a}.partitioned_from.{node_b}"),
                    "true".to_string(),
                );
                self.state.insert(
                    format!("{node_b}.partitioned_from.{node_a}"),
                    "true".to_string(),
                );
                Ok(())
            }
            Step::Other => Err(crate::TestbedError::Validation(
                "unsupported scenario step".to_string(),
            )),
        }
    }

    fn simulator_mut(&mut self, name: &str) -> Result<&mut Simulator, crate::TestbedError> {
        self.simulators.get_mut(name).ok_or_else(|| {
            crate::TestbedError::Validation(format!(
                "scenario references unknown or non-simulated endpoint '{name}'"
            ))
        })
    }
}

/// Kubernetes Kind runner configuration contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KindRunnerConfig {
    pub namespace: String,
    pub service_account: String,
    pub image_pull_policy: String,
    pub dry_run: bool,
}

/// Kubernetes Kind scenario runner.
pub struct KindRunner {
    pub config: KindRunnerConfig,
}

impl KindRunner {
    pub fn new(config: KindRunnerConfig) -> Self {
        Self { config }
    }

    /// Generates Kubernetes manifests representing the scenario plan.
    pub fn generate_manifests(&self, scenario: &Scenario) -> Result<String, crate::TestbedError> {
        // Validation: images, namespaces, service accounts, config maps, etc.
        for (name, spec) in &scenario.topology.nfs {
            if let Some(image) = &spec.image {
                if image.trim().is_empty() {
                    return Err(crate::TestbedError::Validation(format!(
                        "NF {name} has an empty image name"
                    )));
                }
            }
        }

        if self.config.namespace.trim().is_empty() {
            return Err(crate::TestbedError::Validation("namespace is empty".into()));
        }
        if self.config.service_account.trim().is_empty() {
            return Err(crate::TestbedError::Validation(
                "service_account is empty".into(),
            ));
        }

        let mut manifests = String::new();
        manifests.push_str(&format!(
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n---\n",
            self.config.namespace
        ));
        manifests.push_str(&format!(
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {}\n  namespace: {}\n---\n",
            self.config.service_account, self.config.namespace
        ));

        let scenario_yaml = serde_yaml::to_string(scenario).map_err(|e| {
            crate::TestbedError::Validation(format!("cannot serialize scenario: {e}"))
        })?;
        manifests.push_str(&format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: scenario-dsl\n  namespace: {}\ndata:\n  scenario.yaml: |\n",
            self.config.namespace
        ));
        for line in scenario_yaml.lines() {
            manifests.push_str(&format!("    {line}\n"));
        }
        manifests.push_str("---\n");

        for (name, spec) in &scenario.topology.nfs {
            let image = spec.image.as_deref().unwrap_or("opc-simulator:latest");
            manifests.push_str(&format!(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {}\n  namespace: {}\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: {}\n  template:\n    metadata:\n      labels:\n        app: {}\n    spec:\n      serviceAccountName: {}\n      containers:\n      - name: {}\n        image: {}\n        imagePullPolicy: {}\n---\n",
                name, self.config.namespace, name, name, self.config.service_account, name, image, self.config.image_pull_policy
            ));
        }

        Ok(manifests)
    }

    pub fn run(&self, scenario: &Scenario) -> Result<ScenarioEvidence, crate::TestbedError> {
        let _manifests = self.generate_manifests(scenario)?;

        let outcome = if self.config.dry_run {
            ScenarioOutcome::Pass
        } else {
            ScenarioOutcome::Skipped
        };

        let mut evidence = ScenarioEvidence::new(scenario.id.clone(), outcome);
        evidence.requirements = scenario.requirements.clone();
        evidence.mode = Some("kubernetes".to_string());
        evidence.runner_mode = Some("kind".to_string());
        evidence.seed = scenario.seed;
        evidence.artifacts = vec!["manifests.yaml".to_string()];
        if !self.config.dry_run {
            evidence.set_failure_summary(
                "live kind execution is downstream environment owned; SDK runner produced a validated plan only",
            );
        }

        Ok(evidence)
    }
}

/// Hardware-lab runner configuration contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareLabRunnerConfig {
    pub node_selectors: std::collections::HashMap<String, String>,
    pub nic_requirements: Vec<String>,
    pub hugepages: String,
    pub cpu_layout_expectations: String,
    pub sriov_xdp_expectations: String,
    pub dry_run: bool,
    /// Must contain paths or IDs of hardware evidence, otherwise preflight fails closed.
    pub hardware_evidence_ids: Vec<String>,
}

/// Hardware-lab scenario runner.
pub struct HardwareLabRunner {
    pub config: HardwareLabRunnerConfig,
}

impl HardwareLabRunner {
    pub fn new(config: HardwareLabRunnerConfig) -> Self {
        Self { config }
    }

    /// Generates the dry-run provisioning/scheduling plan for the hardware lab.
    pub fn generate_dry_run_plan(
        &self,
        scenario: &Scenario,
    ) -> Result<String, crate::TestbedError> {
        if self.config.hardware_evidence_ids.is_empty() {
            return Err(crate::TestbedError::Validation(
                "missing hardware evidence: fail closed".into(),
            ));
        }

        let mut plan = String::new();
        plan.push_str("=== HARDWARE-LAB DRY-RUN PLAN ===\n");
        plan.push_str(&format!("Scenario: {}\n", scenario.id));
        plan.push_str(&format!(
            "Node Selectors: {:?}\n",
            sanitized_debug(&self.config.node_selectors)
        ));
        plan.push_str(&format!(
            "NIC Requirements: {:?}\n",
            sanitized_debug(&self.config.nic_requirements)
        ));
        plan.push_str(&format!(
            "Hugepages: {}\n",
            sanitized_text(&self.config.hugepages)
        ));
        plan.push_str(&format!(
            "CPU Layout Expectations: {}\n",
            sanitized_text(&self.config.cpu_layout_expectations)
        ));
        plan.push_str(&format!(
            "SR-IOV/XDP Expectations: {}\n",
            sanitized_text(&self.config.sriov_xdp_expectations)
        ));
        plan.push_str(&format!(
            "Hardware Evidence IDs: {:?}\n",
            sanitized_debug(&self.config.hardware_evidence_ids)
        ));

        plan.push_str("Nodes to Provision:\n");
        for name in scenario.topology.nfs.keys() {
            plan.push_str(&format!(
                "- Provisioning hardware resources for NF: {name}\n"
            ));
        }

        Ok(plan)
    }

    pub fn run(&self, scenario: &Scenario) -> Result<ScenarioEvidence, crate::TestbedError> {
        if self.config.hardware_evidence_ids.is_empty() {
            return Err(crate::TestbedError::Validation(
                "missing hardware evidence: fail closed".into(),
            ));
        }

        if self.config.cpu_layout_expectations.contains("invalid") {
            return Err(crate::TestbedError::Validation(
                "CPU layout preflight check failed: invalid layout".into(),
            ));
        }

        let preflight = build_hardware_preflight(&self.config);
        let report =
            opc_node_resources::validate_resource_profile(&preflight.profile, &preflight.context());
        if !report.is_eligible() {
            return Err(crate::TestbedError::Validation(format!(
                "hardware-lab resource preflight failed: {:?}",
                report.errors
            )));
        }

        let outcome = if self.config.dry_run {
            ScenarioOutcome::Pass
        } else {
            // Live execution is operator/environment owned, skip/fail accordingly.
            ScenarioOutcome::Skipped
        };

        let mut evidence = ScenarioEvidence::new(scenario.id.clone(), outcome);
        evidence.requirements = scenario.requirements.clone();
        evidence.mode = Some("hardware-lab".to_string());
        evidence.runner_mode = Some("hardware-lab".to_string());
        evidence.seed = scenario.seed;
        evidence.artifacts = vec!["dry_run_plan.txt".to_string()];
        if !self.config.dry_run {
            evidence.set_failure_summary(
                "live hardware-lab execution is downstream environment owned; SDK runner produced a validated plan only",
            );
        }

        Ok(evidence)
    }
}

fn scenario_endpoint_known(name: &str, simulators: &BTreeMap<String, Simulator>) -> bool {
    simulators.contains_key(name)
}

fn sanitized_debug(value: &impl std::fmt::Debug) -> String {
    sanitized_text(&format!("{value:?}"))
}

fn sanitized_text(value: &str) -> String {
    let mut summary = opc_redaction::RedactionSummary::default();
    opc_redaction::redact_text(value, &mut summary)
}

struct HardwarePreflight {
    profile: opc_node_resources::ResourceProfile,
    node: opc_node_resources::NodeCapabilityReport,
    cpu_layout: opc_node_resources::CpuLayout,
    data_plane_interfaces: Vec<String>,
    sriov_allowlist: opc_node_resources::SriovAllowlistPolicy,
}

impl HardwarePreflight {
    fn context(&self) -> opc_node_resources::ValidationContext<'_> {
        opc_node_resources::ValidationContext {
            node: &self.node,
            cpu_layout: &self.cpu_layout,
            data_plane_interfaces: &self.data_plane_interfaces,
            hugepage_numa_node: self.cpu_layout.numa_node,
            sriov_allowlist: &self.sriov_allowlist,
        }
    }
}

fn build_hardware_preflight(config: &HardwareLabRunnerConfig) -> HardwarePreflight {
    use opc_node_resources::{
        AfXdpProfile, BpfCapabilities, CpuLayout, CpuManagerPolicy, DataPlaneProfile, Environment,
        HugepagePool, KernelVersion, LinkStatePolicy, LinuxCapability, NetworkFunctionKind,
        NicCapability, NodeCapabilityReport, NodeCpuCapabilities, NodeMemoryCapabilities,
        PodSecurityExceptionModel, ResourceProfile, SriovAllowlistPolicy, SriovProfile,
        TopologyManagerPolicy, XdpMode,
    };

    let data_plane_profile = if config.sriov_xdp_expectations.contains("sriov") {
        DataPlaneProfile::SriovFastPath
    } else if config.sriov_xdp_expectations.contains("xdp") {
        DataPlaneProfile::AfXdpFastPath
    } else {
        DataPlaneProfile::ControlPlaneOnly
    };

    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Amf,
        data_plane_profile,
        Environment::Lab,
    );
    profile.pod_security = PodSecurityExceptionModel::minimal_required(
        data_plane_profile,
        Some("hardware-lab-dry-run-evidence".to_string()),
    );

    let data_plane_interfaces = if config.nic_requirements.is_empty()
        || matches!(data_plane_profile, DataPlaneProfile::ControlPlaneOnly)
    {
        Vec::new()
    } else {
        config.nic_requirements.clone()
    };

    if matches!(data_plane_profile, DataPlaneProfile::SriovFastPath) {
        let resource_name = "openpacketcore.io/sriov".to_string();
        profile.sriov = Some(SriovProfile {
            resource_name: resource_name.clone(),
            vf_trust: true,
            spoof_check: true,
            vlan_policy: None,
            link_state_policy: LinkStatePolicy::Auto,
            allowed_device_drivers: BTreeSet::from(["ice".to_string(), "mlx5_core".to_string()]),
            ipam_mode: opc_node_resources::IpamMode::Static,
        });
        profile.lab_fallback.allow_veth = false;
    }

    if matches!(data_plane_profile, DataPlaneProfile::AfXdpFastPath) {
        profile.af_xdp = Some(AfXdpProfile {
            minimum_kernel: KernelVersion::new(6, 1, 0),
            required_btf: true,
            required_xdp_mode: XdpMode::Native,
            required_capabilities: BTreeSet::from([
                LinuxCapability::CapBpf,
                LinuxCapability::CapNetAdmin,
                LinuxCapability::CapNetRaw,
            ]),
            required_maps: vec!["opc_fastpath".to_string()],
            required_pin_paths: vec!["/sys/fs/bpf/opc".to_string()],
            generic_xdp_fallback_allowed: false,
            bpf_artifacts: vec![],
        });
    }

    let nic_names = if data_plane_interfaces.is_empty() {
        vec!["net0".to_string()]
    } else {
        data_plane_interfaces.clone()
    };
    let nics = nic_names
        .iter()
        .map(|name| NicCapability {
            name: name.clone(),
            driver: "ice".to_string(),
            sriov_vfs: 8,
            xdp_modes: BTreeSet::from([XdpMode::Native, XdpMode::Generic]),
            queues: 8,
            numa_node: Some(0),
        })
        .collect();

    let node = NodeCapabilityReport {
        kernel: KernelVersion::new(6, 1, 0),
        bpf: BpfCapabilities {
            cap_bpf: true,
            xdp_supported: true,
            btf_available: true,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::from([XdpMode::Native, XdpMode::Generic]),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::Static,
            isolated_cores: BTreeSet::from([2, 3, 4, 5]),
            numa_nodes: 1,
            cpu_ids: BTreeSet::from([0, 1, 2, 3, 4, 5]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: BTreeMap::from([(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 512,
            hugepages_1gi: 4,
            hugepage_pools: vec![HugepagePool {
                numa_node: 0,
                size: "1Gi".to_string(),
                total: 4,
                free: 4,
            }],
        },
        nics,
    };

    let cpu_layout = if matches!(data_plane_profile, DataPlaneProfile::ControlPlaneOnly) {
        CpuLayout {
            data_plane_cores: vec![],
            control_plane_cores: vec![2, 3],
            management_cores: vec![4],
            numa_node: Some(0),
        }
    } else {
        CpuLayout {
            data_plane_cores: vec![2, 3],
            control_plane_cores: vec![4],
            management_cores: vec![5],
            numa_node: Some(0),
        }
    };

    let mut sriov_allowlist = SriovAllowlistPolicy::default();
    if let Some(sriov) = profile.sriov.as_ref() {
        sriov_allowlist.allowed_resources.insert(
            NetworkFunctionKind::Amf,
            BTreeSet::from([sriov.resource_name.clone()]),
        );
    }

    HardwarePreflight {
        profile,
        node,
        cpu_layout,
        data_plane_interfaces,
        sriov_allowlist,
    }
}
