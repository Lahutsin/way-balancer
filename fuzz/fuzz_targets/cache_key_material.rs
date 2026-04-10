#![no_main]

use libfuzzer_sys::fuzz_target;
use lb_config_model::HttpCachePolicyConfig;
use lb_proto_http::HttpHeader;
use lb_runtime::{build_http_cache_key_material, HttpCacheRequest};

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let host = input.lines().next().unwrap_or("example.test").trim();
        let target = if input.starts_with('/') { input } else { "/" };
        let headers = [HttpHeader {
            name: String::from("host"),
            value: if host.is_empty() { String::from("example.test") } else { host.to_string() },
        }];
        let request = HttpCacheRequest {
            method: "GET",
            target,
            headers: &headers,
        };
        let _ = build_http_cache_key_material(&HttpCachePolicyConfig::default(), &request, &[]);
    }
});