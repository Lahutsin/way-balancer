#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut input = data.to_vec();
    let mut cursor = std::io::Cursor::new(&mut input);
    let mut buffer = Vec::new();
    let limits = lb_proto_http::Http1Limits::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    if let Ok(runtime) = runtime {
        let _ = runtime.block_on(lb_proto_http::read_request_head(
            &mut cursor,
            &mut buffer,
            &limits,
            &[],
        ));
    }
});