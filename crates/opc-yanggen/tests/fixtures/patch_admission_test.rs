
#[cfg(test)]
mod admission_regression {
    use super::*;

    #[test]
    fn private_scalar_admission_precedes_assignment() {
        for (name, accepted, rejected) in [("code", "abc", "123"), ("labels", "abc", "abcd")] {
            let segments = parse_path(name).unwrap();
            let mut baseline = Root::default();
            baseline.apply_patch_segments_inner(&ConfigOp::Update, &segments, Some(accepted)).unwrap();
            assert_eq!(super::super::validate::validate_syntax(&baseline), Ok(()));
            for operation in [ConfigOp::Update, ConfigOp::Merge, ConfigOp::Replace] {
                let mut candidate = baseline.clone();
                let error = candidate.apply_patch_segments_inner(&operation, &segments, Some(rejected)).unwrap_err();
                assert_eq!(error.kind(), "invalid-value");
                assert_eq!(error.message(), "string violates YANG constraints");
                assert_eq!(candidate, baseline);
            }
        }
    }
}
