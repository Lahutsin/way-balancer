use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use crate::{GatewayApiResourceSet, ObjectMeta, ServiceEndpointResource};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryApiVersion {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAddressType {
    Ipv4,
    Ipv6,
    Fqdn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSliceResource {
    pub api_version: DiscoveryApiVersion,
    pub metadata: ObjectMeta,
    pub service_name: String,
    pub generation: u64,
    pub address_type: EndpointAddressType,
    pub ports: Vec<u16>,
    pub endpoints: Vec<EndpointSliceEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSliceEndpoint {
    pub id: String,
    pub addresses: Vec<IpAddr>,
    pub conditions: EndpointSliceConditions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointSliceConditions {
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
}

impl Default for EndpointSliceConditions {
    fn default() -> Self {
        Self { ready: true, serving: true, terminating: false }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSliceUpdateOutcome {
    Accepted,
    IgnoredStale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointSliceApplyError {
    UnsupportedAddressType { namespace: String, name: String },
    MissingPort { namespace: String, name: String },
    MultiplePortsUnsupported { namespace: String, name: String },
    EmptyEndpointAddresses { namespace: String, name: String, endpoint_id: String },
}

impl std::fmt::Display for EndpointSliceApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAddressType { namespace, name } => {
                write!(formatter, "EndpointSlice {namespace}/{name} uses unsupported address_type")
            }
            Self::MissingPort { namespace, name } => {
                write!(formatter, "EndpointSlice {namespace}/{name} must declare one port")
            }
            Self::MultiplePortsUnsupported { namespace, name } => write!(
                formatter,
                "EndpointSlice {namespace}/{name} declares multiple ports; only one is supported"
            ),
            Self::EmptyEndpointAddresses { namespace, name, endpoint_id } => write!(
                formatter,
                "EndpointSlice {namespace}/{name} endpoint {endpoint_id} has no addresses"
            ),
        }
    }
}

impl std::error::Error for EndpointSliceApplyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EndpointSliceStats {
    pub endpoint_update_count: u64,
    pub coalesced_update_count: u64,
    pub stale_update_count: u64,
    pub malformed_update_count: u64,
    pub flush_count: u64,
}

#[derive(Debug, Default)]
pub struct EndpointSliceController {
    slices: BTreeMap<(String, String), EndpointSliceResource>,
    pending_services: BTreeSet<(String, String)>,
    stats: EndpointSliceStats,
}

impl EndpointSliceController {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_slice(
        &mut self,
        slice: EndpointSliceResource,
    ) -> Result<EndpointSliceUpdateOutcome, EndpointSliceApplyError> {
        validate_slice(&slice).inspect_err(|_| {
            self.stats.malformed_update_count = self.stats.malformed_update_count.saturating_add(1);
        })?;

        let key = (slice.metadata.namespace.clone(), slice.metadata.name.clone());
        if let Some(existing) = self.slices.get(&key) {
            if slice.generation <= existing.generation {
                self.stats.stale_update_count = self.stats.stale_update_count.saturating_add(1);
                return Ok(EndpointSliceUpdateOutcome::IgnoredStale);
            }
        }

        let service_key = (slice.metadata.namespace.clone(), slice.service_name.clone());
        if !self.pending_services.insert(service_key) {
            self.stats.coalesced_update_count = self.stats.coalesced_update_count.saturating_add(1);
        }
        self.slices.insert(key, slice);
        self.stats.endpoint_update_count = self.stats.endpoint_update_count.saturating_add(1);
        Ok(EndpointSliceUpdateOutcome::Accepted)
    }

    pub fn delete_slice(&mut self, namespace: &str, slice_name: &str) -> bool {
        let key = (String::from(namespace), String::from(slice_name));
        let removed = self.slices.remove(&key);
        if let Some(slice) = removed {
            let service_key = (slice.metadata.namespace.clone(), slice.service_name.clone());
            if !self.pending_services.insert(service_key) {
                self.stats.coalesced_update_count =
                    self.stats.coalesced_update_count.saturating_add(1);
            }
            self.stats.endpoint_update_count = self.stats.endpoint_update_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    pub fn flush_into(&mut self, resources: &GatewayApiResourceSet) -> GatewayApiResourceSet {
        let mut next = resources.clone();
        for service in &mut next.services {
            let key = (service.metadata.namespace.clone(), service.metadata.name.clone());
            if !self.pending_services.contains(&key) {
                continue;
            }

            let mut endpoints = self
                .slices
                .values()
                .filter(|slice| {
                    slice.metadata.namespace == service.metadata.namespace
                        && slice.service_name == service.metadata.name
                })
                .flat_map(|slice| {
                    slice.endpoints.iter().filter_map(|endpoint| {
                        if !endpoint.conditions.ready
                            || !endpoint.conditions.serving
                            || endpoint.conditions.terminating
                        {
                            return None;
                        }
                        let port = slice.ports[0];
                        Some(ServiceEndpointResource {
                            id: endpoint.id.clone(),
                            address: SocketAddr::new(endpoint.addresses[0], port),
                        })
                    })
                })
                .collect::<Vec<_>>();
            endpoints.sort_by(|left, right| left.id.cmp(&right.id));
            service.endpoints = endpoints;
        }

        if !self.pending_services.is_empty() {
            self.stats.flush_count = self.stats.flush_count.saturating_add(1);
            self.pending_services.clear();
        }
        next
    }

    #[must_use]
    pub const fn stats(&self) -> EndpointSliceStats {
        self.stats
    }

    #[must_use]
    pub fn slice_refs(&self) -> Vec<(String, String)> {
        self.slices.keys().map(|(namespace, name)| (namespace.clone(), name.clone())).collect()
    }
}

fn validate_slice(slice: &EndpointSliceResource) -> Result<(), EndpointSliceApplyError> {
    if slice.address_type == EndpointAddressType::Fqdn {
        return Err(EndpointSliceApplyError::UnsupportedAddressType {
            namespace: slice.metadata.namespace.clone(),
            name: slice.metadata.name.clone(),
        });
    }
    if slice.ports.is_empty() {
        return Err(EndpointSliceApplyError::MissingPort {
            namespace: slice.metadata.namespace.clone(),
            name: slice.metadata.name.clone(),
        });
    }
    if slice.ports.len() != 1 {
        return Err(EndpointSliceApplyError::MultiplePortsUnsupported {
            namespace: slice.metadata.namespace.clone(),
            name: slice.metadata.name.clone(),
        });
    }
    for endpoint in &slice.endpoints {
        if endpoint.addresses.is_empty() {
            return Err(EndpointSliceApplyError::EmptyEndpointAddresses {
                namespace: slice.metadata.namespace.clone(),
                name: slice.metadata.name.clone(),
                endpoint_id: endpoint.id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        DiscoveryApiVersion, EndpointAddressType, EndpointSliceApplyError, EndpointSliceConditions,
        EndpointSliceController, EndpointSliceEndpoint, EndpointSliceResource,
        EndpointSliceUpdateOutcome,
    };
    use crate::{
        BackendReferenceResource, CoreApiVersion, GatewayApiResourceSet, GatewayApiVersion,
        GatewayClassResource, GatewayListenerProtocol, GatewayListenerResource,
        GatewayParentReference, GatewayResource, HttpRouteMatchResource, HttpRouteResource,
        HttpRouteRuleResource, ObjectMeta, ServiceEndpointResource, ServicePortResource,
        ServiceResource, SUPPORTED_GATEWAY_CONTROLLER_NAME,
    };

    fn base_resources() -> GatewayApiResourceSet {
        GatewayApiResourceSet {
            gateway_classes: vec![GatewayClassResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("cluster", "public-gateway"),
                controller_name: String::from(SUPPORTED_GATEWAY_CONTROLLER_NAME),
            }],
            gateways: vec![GatewayResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("edge", "public"),
                gateway_class_name: String::from("public-gateway"),
                listeners: vec![GatewayListenerResource {
                    name: String::from("web"),
                    port: 8080,
                    protocol: GatewayListenerProtocol::Http,
                    hostname: None,
                }],
            }],
            http_routes: vec![HttpRouteResource {
                api_version: GatewayApiVersion::V1,
                metadata: ObjectMeta::new("edge", "payments"),
                hostnames: Vec::new(),
                parent_refs: vec![GatewayParentReference {
                    gateway_name: String::from("public"),
                    gateway_namespace: None,
                    section_name: Some(String::from("web")),
                }],
                rules: vec![HttpRouteRuleResource {
                    matches: vec![HttpRouteMatchResource {
                        path_prefix: String::from("/payments"),
                    }],
                    backend_refs: vec![BackendReferenceResource {
                        service_name: String::from("payments"),
                        port: 8080,
                    }],
                }],
            }],
            services: vec![ServiceResource {
                api_version: CoreApiVersion::V1,
                metadata: ObjectMeta::new("edge", "payments"),
                ports: vec![ServicePortResource { port: 8080, name: None }],
                endpoints: vec![ServiceEndpointResource {
                    id: String::from("bootstrap"),
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
                }],
            }],
        }
    }

    fn slice(generation: u64, endpoint_ids: &[&str]) -> EndpointSliceResource {
        EndpointSliceResource {
            api_version: DiscoveryApiVersion::V1,
            metadata: ObjectMeta::new("edge", "payments-a"),
            service_name: String::from("payments"),
            generation,
            address_type: EndpointAddressType::Ipv4,
            ports: vec![8081],
            endpoints: endpoint_ids
                .iter()
                .enumerate()
                .map(|(index, id)| EndpointSliceEndpoint {
                    id: String::from(*id),
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10 + index as u8))],
                    conditions: EndpointSliceConditions::default(),
                })
                .collect(),
        }
    }

    #[test]
    fn endpoint_slice_changes_update_internal_service_endpoints() {
        let mut controller = EndpointSliceController::new();
        let resources = base_resources();

        let outcome = controller.upsert_slice(slice(1, &["payments-a", "payments-b"]));

        assert_eq!(outcome, Ok(EndpointSliceUpdateOutcome::Accepted));
        let next = controller.flush_into(&resources);
        assert_eq!(next.services[0].endpoints.len(), 2);
        assert_eq!(next.services[0].endpoints[0].id, "payments-a");
    }

    #[test]
    fn churn_is_coalesced_before_flush() {
        let mut controller = EndpointSliceController::new();

        let _ = controller.upsert_slice(slice(1, &["payments-a"]));
        let _ = controller.upsert_slice(slice(2, &["payments-a", "payments-b"]));

        assert_eq!(controller.stats().coalesced_update_count, 1);
        let _ = controller.flush_into(&base_resources());
        assert_eq!(controller.stats().flush_count, 1);
    }

    #[test]
    fn stale_updates_are_ignored_and_counted() {
        let mut controller = EndpointSliceController::new();

        let first = controller.upsert_slice(slice(3, &["payments-a"]));
        let stale = controller.upsert_slice(slice(2, &["payments-b"]));

        assert_eq!(first, Ok(EndpointSliceUpdateOutcome::Accepted));
        assert_eq!(stale, Ok(EndpointSliceUpdateOutcome::IgnoredStale));
        assert_eq!(controller.stats().stale_update_count, 1);
    }

    #[test]
    fn malformed_or_unsupported_slices_are_rejected_safely() {
        let mut controller = EndpointSliceController::new();
        let mut malformed = slice(1, &["payments-a"]);
        malformed.address_type = EndpointAddressType::Fqdn;

        let result = controller.upsert_slice(malformed);

        assert!(matches!(result, Err(EndpointSliceApplyError::UnsupportedAddressType { .. })));
        assert_eq!(controller.stats().malformed_update_count, 1);
    }

    #[test]
    fn non_ready_or_terminating_endpoints_do_not_surface_as_ready() {
        let mut controller = EndpointSliceController::new();
        let resources = base_resources();
        let mut slice = slice(1, &["payments-a", "payments-b"]);
        slice.endpoints[0].conditions.ready = false;
        slice.endpoints[1].conditions.terminating = true;

        let _ = controller.upsert_slice(slice);
        let next = controller.flush_into(&resources);

        assert!(next.services[0].endpoints.is_empty());
    }
}
