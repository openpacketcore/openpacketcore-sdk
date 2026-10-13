use super::*;

fn selected_policy(paths: &[&str], action: NacmAction) -> NacmPolicy {
    let modules = module_registry();
    let mut policy = NacmPolicy::builder(opc_nacm::PolicyVersion::new(1));
    for path in paths {
        policy = policy.add_rule(NacmRule::allow(
            action,
            YangPathPattern::parse(path, &modules).expect("schema path"),
        ));
    }
    policy.build()
}

fn selected_get(path: &str) -> gnmi::GetRequest {
    gnmi::GetRequest {
        path: vec![crate::get::yang_path_to_proto(&YangPath::new(path).unwrap()).unwrap()],
        r#type: gnmi::get_request::DataType::Config as i32,
        encoding: gnmi::Encoding::JsonIetf as i32,
        ..Default::default()
    }
}

#[tokio::test]
async fn denied_key_omits_entry() {
    let service = authenticated_service_with_policy(selected_policy(
        &["/sys:system/sys:user/sys:role"],
        NacmAction::Read,
    ))
    .await;
    for path in [
        "/sys:system",
        "/sys:system/sys:user[sys:name='admin']/sys:role",
        "/sys:system/sys:user[sys:name='absent-hidden-marker']/sys:role",
    ] {
        let response = service
            .get(authenticated_get_request(selected_get(path)))
            .await
            .expect("denied keys omit entries without an error")
            .into_inner();
        assert_eq!(response.notification, Vec::new());
        assert_eq!(response.error, None);
    }
}

struct AlternatingPolicy {
    calls: AtomicUsize,
}

impl PolicySource for AlternatingPolicy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let path = if self.calls.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
            "/sys:system/sys:user/sys:role"
        } else {
            "/sys:system/sys:user/sys:name"
        };
        Ok(Arc::new(selected_policy(&[path], NacmAction::Read)))
    }
}

#[tokio::test]
async fn key_dependencies_share_one_policy_snapshot() {
    let policy = Arc::new(AlternatingPolicy {
        calls: AtomicUsize::new(0),
    });
    let service = authenticated_service_with_policy_source_operational_audit(
        policy.clone(),
        Arc::new(TestOperationalState),
        Arc::new(CapturingAudit::default()),
    )
    .await;
    for call in 1..=4 {
        let response = service
            .get(authenticated_get_request(selected_get(
                "/sys:system/sys:user[sys:name='admin']/sys:role",
            )))
            .await
            .expect("read")
            .into_inner();
        assert_eq!(policy.calls.load(Ordering::SeqCst), call);
        assert_eq!(response.notification, Vec::new());
    }
}

#[test]
fn sensitive_key_outputs_are_value_free() {
    let marker = "diagnostic-sensitive-key-marker";
    let path = YangPath::new(format!(
        "/sys:system/sys:user[sys:name='{marker}']/sys:role"
    ))
    .unwrap();
    let selection = crate::ReadSelectionEntry::new("/sys:system/sys:user/sys:role", path.clone());
    let update = GnmiJsonUpdate::new(path.clone(), format!("\"{marker}\"")).unwrap();
    let value = OperationalValue::new(path.clone(), format!("\"{marker}\"")).unwrap();
    for diagnostic in [
        format!("{selection:?}"),
        format!("{update:?}"),
        format!("{value:?}"),
        format!("{:?}", OperationalEvent::Delete { path }),
    ] {
        assert!(
            !diagnostic.contains(marker),
            "path-bearing diagnostics must omit values"
        );
    }
}
