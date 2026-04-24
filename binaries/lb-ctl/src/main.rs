fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|error| {
        format!("required environment variable {name} is missing or invalid: {error}").into()
    })
}

fn control_plane_signer() -> Result<lb_config_model::ArtifactSigner, Box<dyn std::error::Error>> {
    let signer_identity = std::env::var("LB_CONTROL_PLANE_SIGNER_IDENTITY")
        .unwrap_or_else(|_| String::from("control-plane"));
    let signing_key = required_env("LB_CONTROL_PLANE_SIGNING_KEY_ED25519")?;

    lb_config_model::ArtifactSigner::from_signing_key_hex(signer_identity, &signing_key)
        .map_err(Into::into)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Demo,
    Preview {
        candidate_version: String,
        baseline_version: Option<String>,
    },
    Apply {
        candidate_version: String,
        baseline_version: Option<String>,
        allow_staged_apply: bool,
    },
}

fn parse_cli_command_from_args(args: &[String]) -> Result<CliCommand, String> {
    if args.len() <= 1 {
        return Ok(CliCommand::Demo);
    }
    if args[1].starts_with('-') {
        return Ok(CliCommand::Demo);
    }

    let mut candidate_version = String::from("canary-v2");
    let mut baseline_version = Some(String::from("stable-v1"));
    let mut allow_staged_apply = false;
    let command = args[1].as_str();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--candidate" => {
                index += 1;
                if index >= args.len() {
                    return Err(String::from("--candidate requires a value"));
                }
                candidate_version = args[index].clone();
            }
            "--baseline" => {
                index += 1;
                if index >= args.len() {
                    return Err(String::from("--baseline requires a value"));
                }
                baseline_version = Some(args[index].clone());
            }
            "--no-baseline" => baseline_version = None,
            "--allow-staged-apply" => allow_staged_apply = true,
            flag => return Err(format!("unsupported argument: {flag}")),
        }
        index += 1;
    }

    match command {
        "demo" => Ok(CliCommand::Demo),
        "preview" => Ok(CliCommand::Preview {
            candidate_version,
            baseline_version,
        }),
        "apply" => Ok(CliCommand::Apply {
            candidate_version,
            baseline_version,
            allow_staged_apply,
        }),
        other => Err(format!(
            "unknown command '{other}'; expected one of: demo, preview, apply"
        )),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_command = parse_cli_command_from_args(&std::env::args().collect::<Vec<_>>())
        .map_err(|error| format!("invalid lb-ctl command: {error}"))?;

    let signer = control_plane_signer()?;
    let trusted_signer = signer.trusted_signer();
    let admin_secret = required_env("LB_CTL_ADMIN_SECRET")?;
    let operator_secret = required_env("LB_CTL_OPERATOR_SECRET")?;

    let mut auth = lb_admin_api::AdminAuthService::from_credentials(vec![
        lb_admin_api::AdminCredential {
            token_id: String::from("lb-ctl-admin"),
            principal: String::from("lb-ctl"),
            secret: admin_secret.clone(),
            role: lb_admin_api::AdminRole::Admin,
        },
        lb_admin_api::AdminCredential {
            token_id: String::from("lb-ctl-operator"),
            principal: String::from("lb-ctl"),
            secret: operator_secret.clone(),
            role: lb_admin_api::AdminRole::Operator,
        },
    ])?;
    let admin_token = Some(admin_secret.as_str());
    let operator_token = Some(operator_secret.as_str());

    let stable = lb_config_model::WorkspaceConfig::foundation();
    let mut canary = lb_config_model::WorkspaceConfig::foundation();
    let mut stable = stable;
    stable.security.artifact_verification.trusted_signers = vec![trusted_signer.clone()];
    canary.name = String::from("way-balancer-canary");
    canary.security.artifact_verification.trusted_signers = vec![trusted_signer];

    let status = lb_admin_api::AdminStatus::from(stable.clone());
    let stable_snapshot = stable.compile_snapshot()?;
    let canary_snapshot = canary.compile_snapshot()?;

    let mut control = lb_admin_api::SnapshotControlService::new();
    let stable_attestation = signer.attest_snapshot(&stable_snapshot);
    let _ = auth.publish_snapshot(
        &mut control,
        admin_token,
        lb_admin_api::SnapshotPublishRequest {
            version: String::from("stable-v1"),
            expected_digest_sha256: Some(stable_snapshot.metadata().digest_sha256().to_owned()),
            artifact_attestation: Some(stable_attestation),
            snapshot: stable_snapshot,
            published_by: Some(String::from("lb-ctl")),
            reason: Some(String::from("seed stable version")),
        },
    )?;
    let canary_attestation = signer.attest_snapshot(&canary_snapshot);
    let _ = auth.publish_snapshot(
        &mut control,
        admin_token,
        lb_admin_api::SnapshotPublishRequest {
            version: String::from("canary-v2"),
            expected_digest_sha256: Some(canary_snapshot.metadata().digest_sha256().to_owned()),
            artifact_attestation: Some(canary_attestation),
            snapshot: canary_snapshot,
            published_by: Some(String::from("lb-ctl")),
            reason: Some(String::from("seed canary version")),
        },
    )?;

    let mut dataplane = lb_runtime::DataplaneSnapshotManager::new();
    let mut rollout = lb_admin_api::RolloutCoordinator::new();
    let mut promotion = lb_admin_api::PromotionCoordinator::new();

    match cli_command {
        CliCommand::Preview {
            candidate_version,
            baseline_version,
        } => {
            let preview = auth.preview_promotion(
                &control,
                &mut promotion,
                operator_token,
                lb_admin_api::PromotionPreviewRequest {
                    candidate_version,
                    baseline_version,
                    requested_by: Some(String::from("lb-ctl")),
                    reason: Some(String::from("operator preview")),
                },
            )?;
            println!(
                "lb-ctl promotion preview: candidate={} base_version={} total_changes={} severity={:?} strategy={:?} requires_ack={}",
                preview.candidate_version,
                preview.preview.base_version,
                preview.preview.impact_analysis.total_changes,
                preview.preview.impact_analysis.severity,
                preview.recommended_strategy,
                preview.requires_staged_apply_ack,
            );
            return Ok(());
        }
        CliCommand::Apply {
            candidate_version,
            baseline_version,
            allow_staged_apply,
        } => {
            let _ = auth.rollout_snapshot(
                &control,
                &mut rollout,
                &mut dataplane,
                operator_token,
                lb_admin_api::RolloutRequest {
                    version: String::from("stable-v1"),
                    requested_by: Some(String::from("lb-ctl")),
                    reason: Some(String::from("activate stable baseline before promotion apply")),
                },
            )?;
            let applied = auth.apply_promotion(
                &control,
                &mut promotion,
                &mut rollout,
                &mut dataplane,
                operator_token,
                lb_admin_api::PromotionApplyRequest {
                    candidate_version,
                    baseline_version,
                    requested_by: Some(String::from("lb-ctl")),
                    reason: Some(String::from("operator apply")),
                    allow_staged_apply,
                },
            )?;
            println!(
                "lb-ctl promotion apply: candidate={} base_version={} severity={:?} strategy={:?} result={:?} active={} last_good={}",
                applied.preview.candidate_version,
                applied.preview.preview.base_version,
                applied.preview.preview.impact_analysis.severity,
                applied.preview.recommended_strategy,
                applied.rollout.result,
                applied.rollout.active_version,
                applied.rollout.last_known_good_version,
            );
            return Ok(());
        }
        CliCommand::Demo => {}
    }

    let publish_preview = auth
        .preview_promotion(
            &control,
            &mut promotion,
            operator_token,
            lb_admin_api::PromotionPreviewRequest {
                candidate_version: String::from("canary-v2"),
                baseline_version: Some(String::from("stable-v1")),
                requested_by: Some(String::from("lb-ctl")),
                reason: Some(String::from("demo preview")),
            },
        )
        .ok();

    let stable_rollout = auth.rollout_snapshot(
        &control,
        &mut rollout,
        &mut dataplane,
        operator_token,
        lb_admin_api::RolloutRequest {
            version: String::from("stable-v1"),
            requested_by: Some(String::from("lb-ctl")),
            reason: Some(String::from("activate stable baseline")),
        },
    )?;
    let canary_rollout = auth.rollout_snapshot(
        &control,
        &mut rollout,
        &mut dataplane,
        operator_token,
        lb_admin_api::RolloutRequest {
            version: String::from("canary-v2"),
            requested_by: Some(String::from("lb-ctl")),
            reason: Some(String::from("exercise operator rollout")),
        },
    )?;
    let rollback = auth.rollback_snapshot(
        &control,
        &mut rollout,
        &mut dataplane,
        operator_token,
        lb_admin_api::RollbackRequest {
            target_version: None,
            requested_by: Some(String::from("lb-ctl")),
            reason: Some(String::from("return to previous known-good")),
        },
    )?;
    let visible_versions = auth.list_versions(&control, operator_token)?;
    let status_target = lb_admin_api::versioned_admin_target("/status");

    println!(
        "lb-ctl rollout ready: api_version={} status_target={} config={} published_versions={} visible_versions={} preview_base={:?} preview_total_changes={:?} preview_severity={:?} stable={:?} canary={:?} rollback={:?} active={} last_good={} history={} auth_audit_events={}",
        lb_admin_api::STABLE_ADMIN_API_VERSION,
        status_target,
        status.config_name,
        control.list_versions().len(),
        visible_versions.len(),
        publish_preview
            .as_ref()
            .map(|preview| preview.preview.base_version.as_str()),
        publish_preview
            .as_ref()
            .map(|preview| preview.preview.impact_analysis.total_changes),
        publish_preview
            .as_ref()
            .map(|preview| preview.preview.impact_analysis.severity),
        stable_rollout.result,
        canary_rollout.result,
        rollback.result,
        rollback.active_version,
        rollback.last_known_good_version,
        rollout.history().len(),
        auth.audit_history().len(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_cli_command_from_args, CliCommand};

    #[test]
    fn parse_preview_command_with_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let command = parse_cli_command_from_args(&[
            String::from("lb-ctl"),
            String::from("preview"),
        ])?;
        assert!(matches!(
            command,
            CliCommand::Preview {
                candidate_version,
                baseline_version
            } if candidate_version == "canary-v2" && baseline_version.as_deref() == Some("stable-v1")
        ));
        Ok(())
    }

    #[test]
    fn parse_apply_command_with_ack_flag() -> Result<(), Box<dyn std::error::Error>> {
        let command = parse_cli_command_from_args(&[
            String::from("lb-ctl"),
            String::from("apply"),
            String::from("--candidate"),
            String::from("canary-v9"),
            String::from("--allow-staged-apply"),
        ])?;
        assert!(matches!(
            command,
            CliCommand::Apply {
                candidate_version,
                allow_staged_apply,
                ..
            } if candidate_version == "canary-v9" && allow_staged_apply
        ));
        Ok(())
    }

    #[test]
    fn binary_smoke_runs_successfully() -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var("LB_CTL_ADMIN_SECRET", "viewer-secret");
        std::env::set_var("LB_CTL_OPERATOR_SECRET", "operator-secret");
        std::env::set_var(
            "LB_CONTROL_PLANE_SIGNING_KEY_ED25519",
            lb_test_support::TEST_SIGNING_KEY_ED25519,
        );
        super::main()
    }
}
