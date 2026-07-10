use std::time::Duration;

use opc_mgmt_command::{
    ActionContract, ActionIdempotency, ActionPlan, CatalogError, CatalogLimits, ColumnSpec,
    CommandGrammar, CommandId, CommandRegistry, CommandSchema, CommandSpec, CommandToken,
    CommandVersion, DataNodeAccess, EffectClass, ExecutionLimits, GrammarNode, HelpText,
    OperationPlan, PresentationSpec, ReadPlan, ReadSource, SchemaPath, TableSpec,
};

struct ReferenceSchema {
    operational: SchemaPath,
    configuration: SchemaPath,
    action: SchemaPath,
    action_result: SchemaPath,
}

impl CommandSchema for ReferenceSchema {
    fn data_node_access(&self, path: &SchemaPath) -> Option<DataNodeAccess> {
        if path == &self.operational {
            Some(DataNodeAccess::Operational)
        } else if path == &self.configuration {
            Some(DataNodeAccess::Configuration)
        } else {
            None
        }
    }

    fn action_contract(&self, path: &SchemaPath) -> Option<ActionContract> {
        (path == &self.action).then_some(ActionContract::new(
            EffectClass::Probe,
            ActionIdempotency::TargetDeduplicated,
        ))
    }

    fn result_field_exists(&self, _operation: &OperationPlan, field: &SchemaPath) -> bool {
        field == &self.operational || field == &self.configuration || field == &self.action_result
    }
}

fn schema() -> ReferenceSchema {
    ReferenceSchema {
        operational: path("/epdg:state/epdg:health"),
        configuration: path("/epdg:config/epdg:name"),
        action: path("/epdg:diagnostics/epdg:ping"),
        action_result: path("/epdg:diagnostics/epdg:ping/epdg:result"),
    }
}

fn path(value: &str) -> SchemaPath {
    SchemaPath::new(value).expect("valid fixture path")
}

fn token(value: &str) -> CommandToken {
    CommandToken::new(value).expect("valid fixture token")
}

fn help(value: &str) -> HelpText {
    HelpText::new(value).expect("valid fixture help")
}

fn execution_limits() -> ExecutionLimits {
    ExecutionLimits::new(Duration::from_secs(5), 1024 * 1024, 1024)
        .expect("valid fixture execution limits")
}

fn grammar(verb: &str, noun: &str) -> CommandGrammar {
    CommandGrammar::new([
        GrammarNode::literal(token(verb), help("Command group")),
        GrammarNode::literal(token(noun), help("Command object")),
    ])
}

fn table(field: SchemaPath) -> PresentationSpec {
    PresentationSpec::Table(TableSpec::new([ColumnSpec::new(help("Value"), field)]))
}

#[test]
fn public_api_freezes_read_config_and_action_commands() {
    let schema = schema();
    let operational = CommandSpec::new(
        CommandId::new("epdg.show-health").expect("command id"),
        CommandVersion::new(1).expect("command version"),
        grammar("show", "health"),
        help("Display ePDG health"),
        EffectClass::Observe,
        OperationPlan::Get(ReadPlan::new(
            ReadSource::Operational,
            [schema.operational.clone()],
        )),
        table(schema.operational.clone()),
        execution_limits(),
    );
    let configuration = CommandSpec::new(
        CommandId::new("epdg.show-configured-name").expect("command id"),
        CommandVersion::new(1).expect("command version"),
        grammar("show", "configured-name"),
        help("Display the configured ePDG name"),
        EffectClass::Observe,
        OperationPlan::Get(ReadPlan::new(
            ReadSource::RunningConfig,
            [schema.configuration.clone()],
        )),
        table(schema.configuration.clone()),
        execution_limits(),
    );
    let action = CommandSpec::new(
        CommandId::new("epdg.diagnose-ping").expect("command id"),
        CommandVersion::new(1).expect("command version"),
        grammar("diagnose", "ping"),
        help("Run a bounded ping"),
        EffectClass::Probe,
        OperationPlan::Invoke(ActionPlan::new(
            schema.action.clone(),
            ActionIdempotency::TargetDeduplicated,
        )),
        table(schema.action_result.clone()),
        execution_limits(),
    );

    let mut registry = CommandRegistry::new();
    registry.register(operational).expect("register read");
    registry
        .register(configuration)
        .expect("register config read");
    registry.register(action).expect("register action");

    let catalog = registry
        .freeze(&schema, CatalogLimits::default())
        .expect("freeze public catalog");
    assert_eq!(catalog.commands().len(), 3);
    assert!(catalog
        .command(&CommandId::new("epdg.diagnose-ping").expect("lookup id"))
        .is_some());
}

#[test]
fn public_api_rejects_effect_operation_mismatch() {
    let schema = schema();
    let command = CommandSpec::new(
        CommandId::new("epdg.monitor-health").expect("command id"),
        CommandVersion::new(1).expect("command version"),
        grammar("monitor", "health"),
        help("Monitor ePDG health"),
        EffectClass::Monitor,
        OperationPlan::Get(ReadPlan::new(
            ReadSource::Operational,
            [schema.operational.clone()],
        )),
        table(schema.operational.clone()),
        execution_limits(),
    );
    let mut registry = CommandRegistry::new();
    registry.register(command).expect("register command");

    assert!(matches!(
        registry.freeze(&schema, CatalogLimits::default()),
        Err(CatalogError::EffectOperationMismatch { .. })
    ));
}

#[test]
fn public_api_rejects_action_outside_server_allowlist() {
    let schema = schema();
    let unknown_action = path("/epdg:diagnostics/epdg:restart");
    let command = CommandSpec::new(
        CommandId::new("epdg.diagnose-restart").expect("command id"),
        CommandVersion::new(1).expect("command version"),
        grammar("diagnose", "restart"),
        help("Attempt an unregistered action"),
        EffectClass::Probe,
        OperationPlan::Invoke(ActionPlan::new(
            unknown_action,
            ActionIdempotency::TargetDeduplicated,
        )),
        table(schema.action_result.clone()),
        execution_limits(),
    );
    let mut registry = CommandRegistry::new();
    registry.register(command).expect("register command");

    assert!(matches!(
        registry.freeze(&schema, CatalogLimits::default()),
        Err(CatalogError::UnknownAction { .. })
    ));
}
