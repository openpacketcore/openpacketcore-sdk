use super::*;

async fn assert_masked_configuration_xpath_is_refused(nmda: bool) {
    for permitted in [false, true] {
        for guess in ["correct-marker", "wrong-marker"] {
            let allowed: &[&str] = if permitted {
                &["/ex:system", "/ex:system/**"]
            } else {
                &[]
            };
            let (server, binding, source, audit) = fixture(vec![], vec![policy(allowed)]).await;
            let expression = format!("/p:system/p:sealed[p:id='{guess}']/p:id");
            let operation = if nmda {
                format!(
                    r#"<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores" xmlns:p="urn:example"><datastore>ds:operational</datastore><xpath-filter>{expression}</xpath-filter></get-data>"#
                )
            } else {
                format!(
                    r#"<get><filter xmlns:p="urn:example" type="xpath" select="{expression}"/></get>"#
                )
            };
            let reply = rpc(&server, &operation, &MgmtLimits::default());
            assert!(
                reply.contains("<error-tag>operation-not-supported</error-tag>"),
                "{reply}"
            );
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
            assert!(binding.provider.requests.lock().unwrap().is_empty());
            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
            assert!(!reply.contains(guess));
            assert!(!format!("{:?}", audit.0.lock().unwrap()).contains(guess));
        }
    }
}

#[tokio::test]
async fn get_refuses_masked_configuration_xpath_before_access() {
    assert_masked_configuration_xpath_is_refused(false).await;
}

#[tokio::test]
async fn operational_get_data_refuses_masked_configuration_xpath_before_access() {
    assert_masked_configuration_xpath_is_refused(true).await;
}
