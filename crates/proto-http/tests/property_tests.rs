use lb_proto_http::{
    canonicalize_request_target, match_route_request, RoutePrefixRule,
};
use proptest::prelude::*;

fn safe_path_segment() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            Just('a'),
            Just('b'),
            Just('c'),
            Just('x'),
            Just('y'),
            Just('z'),
            Just('0'),
            Just('1'),
            Just('2'),
            Just('-'),
            Just('_'),
        ],
        1..8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

fn safe_query_component() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            Just('a'),
            Just('b'),
            Just('c'),
            Just('m'),
            Just('n'),
            Just('0'),
            Just('1'),
            Just('2'),
            Just('-'),
            Just('_'),
            Just('f'),
            Just('g'),
        ],
        1..8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

proptest! {
    #[test]
    fn canonical_request_target_query_pairs_are_sorted(
        path in prop::collection::vec(safe_path_segment(), 1..4),
        pairs in prop::collection::vec((safe_query_component(), safe_query_component()), 1..6),
    ) {
        let joined_path = format!("/{}", path.join("/"));
        let raw_query = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let target = format!("{joined_path}?{raw_query}");

        let canonical = match canonicalize_request_target(&target) {
            Ok(canonical) => canonical,
            Err(error) => {
                prop_assert!(false, "target should canonicalize: {error:?}");
                return Ok(());
            }
        };
        let canonical_pairs = canonical.query_pairs.clone();
        let mut expected_pairs = canonical_pairs.clone();
        expected_pairs.sort();

        prop_assert_eq!(canonical_pairs, expected_pairs);
    }

    #[test]
    fn route_matching_prefers_longest_prefix(
        suffix in safe_path_segment(),
    ) {
        let rules = vec![
            RoutePrefixRule::new("root", "/"),
            RoutePrefixRule::new("api", "/api"),
            RoutePrefixRule::new("api-v1", "/api/v1"),
        ];
        let target = format!("/api/v1/{suffix}");

        let matched = match_route_request(&target, None, &rules);

        prop_assert_eq!(matched.map(|route| route.label), Some(String::from("api-v1")));
    }
}