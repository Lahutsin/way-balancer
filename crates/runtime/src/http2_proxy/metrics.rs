struct MetricsState {
    active_streams: AtomicUsize,
    peak_active_streams: AtomicUsize,
    request_count: AtomicU64,
    stream_reset_count: AtomicU64,
    stream_error_count: AtomicU64,
    stream_limit_violation_count: AtomicU64,
    body_limit_violation_count: AtomicU64,
    mirror_dispatch_count: AtomicU64,
    mirror_skip_count: AtomicU64,
    mirror_dispatch_failure_count: AtomicU64,
    fault_injection_delay_count: AtomicU64,
    fault_injection_abort_count: AtomicU64,
    grpc_request_count: AtomicU64,
    grpc_service_counts: Mutex<BTreeMap<String, u64>>,
    grpc_method_counts: Mutex<BTreeMap<String, u64>>,
    grpc_status_counts: Mutex<BTreeMap<u16, u64>>,
    hardening_rejection_count: AtomicU64,
    slow_client_trigger_count: AtomicU64,
    anomaly_counts: Mutex<BTreeMap<ProtocolAnomalyCategory, u64>>,
    slow_client_counts: Mutex<BTreeMap<SlowClientStage, u64>>,
    response_status_counts: Mutex<BTreeMap<u16, u64>>,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            active_streams: AtomicUsize::new(0),
            peak_active_streams: AtomicUsize::new(0),
            request_count: AtomicU64::new(0),
            stream_reset_count: AtomicU64::new(0),
            stream_error_count: AtomicU64::new(0),
            stream_limit_violation_count: AtomicU64::new(0),
            body_limit_violation_count: AtomicU64::new(0),
            mirror_dispatch_count: AtomicU64::new(0),
            mirror_skip_count: AtomicU64::new(0),
            mirror_dispatch_failure_count: AtomicU64::new(0),
            fault_injection_delay_count: AtomicU64::new(0),
            fault_injection_abort_count: AtomicU64::new(0),
            grpc_request_count: AtomicU64::new(0),
            grpc_service_counts: Mutex::new(BTreeMap::new()),
            grpc_method_counts: Mutex::new(BTreeMap::new()),
            grpc_status_counts: Mutex::new(BTreeMap::new()),
            hardening_rejection_count: AtomicU64::new(0),
            slow_client_trigger_count: AtomicU64::new(0),
            anomaly_counts: Mutex::new(BTreeMap::new()),
            slow_client_counts: Mutex::new(BTreeMap::new()),
            response_status_counts: Mutex::new(BTreeMap::new()),
        }
    }

    fn snapshot(&self) -> Http2ConnectionMetrics {
        let grpc_service_counts = self
            .grpc_service_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let grpc_method_counts = self
            .grpc_method_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let grpc_status_counts =
            self.grpc_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let response_status_counts = self
            .response_status_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let anomaly_counts =
            self.anomaly_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let slow_client_counts =
            self.slow_client_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        Http2ConnectionMetrics {
            active_streams: self.active_streams.load(Ordering::SeqCst),
            peak_active_streams: self.peak_active_streams.load(Ordering::SeqCst),
            request_count: self.request_count.load(Ordering::SeqCst),
            stream_reset_count: self.stream_reset_count.load(Ordering::SeqCst),
            stream_error_count: self.stream_error_count.load(Ordering::SeqCst),
            stream_limit_violation_count: self.stream_limit_violation_count.load(Ordering::SeqCst),
            body_limit_violation_count: self.body_limit_violation_count.load(Ordering::SeqCst),
            mirror_dispatch_count: self.mirror_dispatch_count.load(Ordering::SeqCst),
            mirror_skip_count: self.mirror_skip_count.load(Ordering::SeqCst),
            mirror_dispatch_failure_count: self
                .mirror_dispatch_failure_count
                .load(Ordering::SeqCst),
            fault_injection_delay_count: self.fault_injection_delay_count.load(Ordering::SeqCst),
            fault_injection_abort_count: self.fault_injection_abort_count.load(Ordering::SeqCst),
            grpc_request_count: self.grpc_request_count.load(Ordering::SeqCst),
            grpc_service_counts,
            grpc_method_counts,
            grpc_status_counts,
            hardening_rejection_count: self.hardening_rejection_count.load(Ordering::SeqCst),
            slow_client_trigger_count: self.slow_client_trigger_count.load(Ordering::SeqCst),
            anomaly_counts,
            slow_client_counts,
            response_status_counts,
        }
    }

    fn increment_request_count(&self) {
        self.request_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_active_streams(&self) {
        let current = self.active_streams.fetch_add(1, Ordering::SeqCst) + 1;
        let mut observed_peak = self.peak_active_streams.load(Ordering::SeqCst);
        while current > observed_peak {
            match self.peak_active_streams.compare_exchange(
                observed_peak,
                current,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => observed_peak = actual,
            }
        }
    }

    fn decrement_active_streams(&self) {
        let _ = self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }

    fn increment_stream_reset_count(&self) {
        self.stream_reset_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_stream_error_count(&self) {
        self.stream_error_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_stream_limit_violation_count(&self) {
        self.stream_limit_violation_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_body_limit_violation_count(&self) {
        self.body_limit_violation_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_mirror_dispatch_count(&self) {
        self.mirror_dispatch_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_mirror_skip_count(&self) {
        self.mirror_skip_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_mirror_dispatch_failure_count(&self) {
        self.mirror_dispatch_failure_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_fault_injection_delay_count(&self) {
        self.fault_injection_delay_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_fault_injection_abort_count(&self) {
        self.fault_injection_abort_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_grpc_request_count(&self) {
        self.grpc_request_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_grpc_service(&self, service: &str) {
        let mut counts = self
            .grpc_service_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(service.to_string()).or_insert(0) += 1;
    }

    fn record_grpc_method(&self, service: &str, method: &str) {
        let mut counts = self
            .grpc_method_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(format!("{service}/{method}")).or_insert(0) += 1;
    }

    fn record_grpc_status(&self, status: u16) {
        let mut counts =
            self.grpc_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(status).or_insert(0) += 1;
    }

    fn increment_hardening_rejection_count(&self) {
        self.hardening_rejection_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_slow_client_trigger_count(&self) {
        self.slow_client_trigger_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_anomaly(&self, category: ProtocolAnomalyCategory) {
        let mut counts =
            self.anomaly_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(category).or_insert(0) += 1;
    }

    fn record_slow_client(&self, stage: SlowClientStage) {
        let mut counts =
            self.slow_client_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(stage).or_insert(0) += 1;
    }

    fn record_response_status(&self, status: u16) {
        let mut counts =
            self.response_status_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(status).or_insert(0) += 1;
    }
}
