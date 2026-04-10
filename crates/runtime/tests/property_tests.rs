use lb_config_model::{
    AuthorizationCacheBehaviorConfig, CacheKeyPolicyConfig, HttpCachePolicyConfig,
};
use lb_proto_http::HttpHeader;
use lb_runtime::{build_http_cache_key_material, HttpCacheRequest};
use proptest::prelude::*;

fn host_label() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![Just('a'), Just('b'), Just('c'), Just('x'), Just('y'), Just('z'), Just('0'), Just('1'), Just('-')],
        1..8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

fn path_part() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![Just('a'), Just('b'), Just('c'), Just('0'), Just('1'), Just('-'), Just('_')],
        1..8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

proptest! {
    #[test]
    fn cache_key_host_canonicalization_is_case_insensitive(
        host in host_label(),
        path in path_part(),
    ) {
        let policy = HttpCachePolicyConfig {
            authorization: AuthorizationCacheBehaviorConfig::Partition,
            cache_key: CacheKeyPolicyConfig {
                include_host: true,
                include_method: true,
                ..CacheKeyPolicyConfig::default()
            },
            ..HttpCachePolicyConfig::default()
        };

        let lower_host = format!("{}.example.test", host.to_ascii_lowercase());
        let upper_host = lower_host.to_ascii_uppercase();
        let target = format!("/{path}?a=1&b=2");

        let lower_request = HttpCacheRequest {
            method: "GET",
            target: &target,
            headers: &[
                HttpHeader { name: String::from("host"), value: lower_host.clone() },
                HttpHeader { name: String::from("authorization"), value: String::from("Bearer secret-token") },
            ],
        };
        let upper_request = HttpCacheRequest {
            method: "get",
            target: &target,
            headers: &[
                HttpHeader { name: String::from("host"), value: upper_host },
                HttpHeader { name: String::from("authorization"), value: String::from("Bearer secret-token") },
            ],
        };

        let lower_key = match build_http_cache_key_material(&policy, &lower_request, &[]) {
            Ok(Some(material)) => material.primary,
            other => {
                prop_assert!(false, "lower request should build material: {other:?}");
                return Ok(());
            }
        };
        let upper_key = match build_http_cache_key_material(&policy, &upper_request, &[]) {
            Ok(Some(material)) => material.primary,
            other => {
                prop_assert!(false, "upper request should build material: {other:?}");
                return Ok(());
            }
        };

        prop_assert_eq!(lower_key, upper_key);
    }
}