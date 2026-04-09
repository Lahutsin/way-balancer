use lb_test_support::smoke_label;

#[test]
fn workspace_smoke_test_uses_foundation_fixture() {
    assert_eq!(smoke_label(), "lb-runtime");
}
