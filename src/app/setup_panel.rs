//! Local, non-executing setup guidance for the first diagnostic check.

use super::{tw, AivanaApp, View};
use crate::diagnostic_lab::{self, Case, Mode};
use crate::incident::Source;
use crate::mission::Target;
use crate::models::{ConnectionProfile, Protocol};
use eframe::egui::{RichText, Ui};

#[derive(Clone)]
pub(super) struct Snapshot {
    pub incident: String,
    pub service: String,
    pub application: String,
    pub dependency: String,
    pub mode: Mode,
    pub source: Option<Source>,
    pub selected_case: Option<Case>,
    pub store_error: bool,
    pub awaiting_approval: bool,
    pub running: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ready,
    NeedsInput,
    Unknown,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready (configuration)",
            Self::NeedsInput => "Needs input",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone)]
struct Item {
    title: &'static str,
    status: Status,
    detail: String,
    next: Option<(View, &'static str)>,
}

fn item(
    title: &'static str,
    status: Status,
    detail: impl Into<String>,
    next: Option<(View, &'static str)>,
) -> Item {
    Item {
        title,
        status,
        detail: detail.into(),
        next,
    }
}

fn reserved_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "example.com"
        || host.ends_with(".example.com")
        || host == "example.org"
        || host.ends_with(".example.org")
        || host == "example.net"
        || host.ends_with(".example.net")
        || host == "invalid"
        || host.ends_with(".invalid")
        || host == "test"
        || host.ends_with(".test")
}

fn url_ready(raw: &str, https_only: bool) -> bool {
    diagnostic_lab::checked_url(raw).is_ok_and(|url| {
        (!https_only || url.scheme() == "https")
            && url.host_str().is_some_and(|host| !reserved_host(host))
    })
}

fn local_powershell_present() -> bool {
    #[cfg(windows)]
    {
        std::env::var_os("PATH").is_some_and(|path| {
            std::env::split_paths(&path).any(|folder| folder.join("powershell.exe").is_file())
        })
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn assess(profile: Option<&ConnectionProfile>, snapshot: &Snapshot, powershell: bool) -> Vec<Item> {
    let mut checks = Vec::new();
    let target = profile.map(Target::from_profile);
    let direct = profile.is_some_and(|profile| {
        profile.protocol == Protocol::Rdp
            && target
                .as_ref()
                .is_some_and(|target| target.route.is_empty())
            && crate::operations::Endpoint::new(&profile.host, "", profile.port).is_ok()
            && !reserved_host(&profile.host)
    });
    checks.push(match profile {
        None => item(
            "Saved Windows target",
            Status::NeedsInput,
            "Select a saved direct Windows RDP profile.",
            Some((View::Connections, "Select profile")),
        ),
        Some(profile) if direct => item(
            "Saved Windows target",
            Status::Ready,
            format!(
                "{} · {}:{} · {} · direct profile configuration only; WinRM and network access are untested",
                profile.name,
                profile.host,
                profile.port,
                profile.protocol.label()
            ),
            None,
        ),
        Some(profile) => item(
            "Saved Windows target",
            Status::NeedsInput,
            format!(
                "{} · {}:{} · {}. A valid direct Windows RDP profile is required; a gateway, invalid endpoint, or reserved example host cannot qualify.",
                profile.name,
                profile.host,
                profile.port,
                profile.protocol.label()
            ),
            Some((View::Connections, "Review profile")),
        ),
    });
    checks.push(item(
        "Local transport tool",
        if powershell { Status::Ready } else { Status::NeedsInput },
        if powershell {
            "powershell.exe found locally without running it. Remote WinRM, network access, and permissions remain unknown."
        } else {
            "powershell.exe was not found on the local PATH. Install or expose Windows PowerShell before a live check."
        },
        None,
    ));
    checks.push(item(
        "Authentication identity",
        Status::Unknown,
        "Read-only WinRM uses the current Windows identity and its remote permissions. Saved RDP credentials are not used; authentication is untested.",
        None,
    ));

    let source = snapshot.source.as_ref().or_else(|| {
        snapshot
            .selected_case
            .as_ref()
            .and_then(|case| case.source.as_ref())
    });
    checks.push(match (source, target.as_ref()) {
        (Some(_), _) if snapshot.store_error => item(
            "Incident handoff",
            Status::Unknown,
            "Diagnostic storage could not be read; reopen the original failure before proceeding.",
            Some((View::Incident, "Review failure")),
        ),
        (Some(source), Some(target)) if source.matches(target) => item(
            "Incident handoff",
            Status::Ready,
            format!("Exact failure record {} matches the selected saved endpoint.", source.record_id),
            None,
        ),
        (Some(_), _) => item(
            "Incident handoff",
            Status::NeedsInput,
            "The selected profile no longer matches the incident's exact endpoint. Reopen the failure with its original profile.",
            Some((View::Incident, "Review failure")),
        ),
        (None, _) => item(
            "Incident handoff",
            Status::Unknown,
            "No failure record is linked. You may enter a manual incident, or select a documented failure.",
            Some((View::Incident, "Choose failure")),
        ),
    });

    checks.push(item(
        "Incident description",
        if !snapshot.incident.trim().is_empty() && snapshot.incident.len() <= 4096 {
            Status::Ready
        } else {
            Status::NeedsInput
        },
        if snapshot.incident.trim().is_empty() {
            "Describe the observed failure in Diagnostic Lab."
        } else if snapshot.incident.len() > 4096 {
            "Shorten the incident description to at most 4096 bytes."
        } else {
            "Description entered; its accuracy has not been verified."
        },
        Some((View::Intelligence, "Edit diagnostic case")),
    ));
    let service_valid = !snapshot.service.is_empty()
        && snapshot.service.len() <= 128
        && snapshot
            .service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_- .".contains(&byte))
        && !snapshot.service.eq_ignore_ascii_case("ExampleService");
    checks.push(item(
        "Application service",
        if service_valid {
            Status::Ready
        } else {
            Status::NeedsInput
        },
        if service_valid {
            "Service name entered; remote service state is untested."
        } else {
            "Enter the actual Windows service name; the sample value is not a live prerequisite."
        },
        Some((View::Intelligence, "Edit diagnostic case")),
    ));
    for (title, value, https_only) in [
        ("Application URL", snapshot.application.as_str(), true),
        ("Dependency URL", snapshot.dependency.as_str(), false),
    ] {
        let ready = url_ready(value, https_only);
        checks.push(item(
            title,
            if ready { Status::Ready } else { Status::NeedsInput },
            if ready {
                "URL format entered; reachability and application function are untested."
            } else {
                "Enter a real, approved URL. Reserved/example hosts cannot establish live readiness."
            },
            Some((View::Intelligence, "Edit diagnostic case")),
        ));
    }

    let case = snapshot.selected_case.as_ref();
    let valid_case = case.is_some_and(|case| {
        !snapshot.store_error
            && case.validate().is_ok()
            && case.config.mode == Mode::ReadOnly
            && profile.is_some_and(|profile| {
                case.config
                    .target
                    .as_ref()
                    .is_some_and(|target| target.matches(profile))
            })
            && case
                .config
                .target
                .as_ref()
                .is_some_and(|target| !reserved_host(&target.host))
            && url_ready(&case.config.application, true)
            && url_ready(&case.config.dependency, false)
    });
    checks.push(item(
        "Diagnostic mode and saved case",
        if valid_case { Status::Ready } else { Status::NeedsInput },
        if valid_case {
            "A saved read-only case matches this exact profile. Saving a case does not run a check."
        } else if snapshot.mode == Mode::Simulation || case.is_some_and(|case| case.config.mode == Mode::Simulation) {
            "Simulation is the default/example path. Choose read-only explicitly, review real inputs, then save a matching case."
        } else {
            "No valid saved read-only case matches this profile and its current configuration."
        },
        Some((View::Intelligence, "Review diagnostic case")),
    ));
    checks.push(item(
        "Read-only approval",
        Status::Unknown,
        if snapshot.running {
            "An approved read-only job is running; its outcome is pending."
        } else if snapshot.awaiting_approval {
            "A read-only job is prepared for explicit review and approval in Diagnostic Lab."
        } else {
            "Each live check requires explicit review and approval. No approval is inferred from setup or case save."
        },
        Some((View::Intelligence, "Review read-only check")),
    ));
    let live_observations = valid_case
        .then(|| {
            case.unwrap()
                .observations
                .iter()
                .filter(|observation| observation.mode == Mode::ReadOnly)
                .count()
        })
        .unwrap_or(0);
    checks.push(item(
        "Diagnostic evidence",
        Status::Unknown,
        if snapshot.store_error {
            "Diagnostic storage could not be read. Evidence and readiness cannot be trusted."
        } else if live_observations > 0 {
            "Historical approved read-only observations exist for this case. Current target state and causation remain unverified."
        } else {
            "No live read-only observation for this exact case. Simulation results are examples only."
        },
        Some((View::Intelligence, "Open Diagnostic Lab")),
    ));
    checks.push(item(
        "Functional verification",
        Status::Unknown,
        "Pending. A diagnostic model match does not prove the affected function works or that a repair succeeded; verify it separately with observed evidence.",
        Some((View::Execution, "Review verification workflow")),
    ));
    checks
}

impl AivanaApp {
    pub(super) fn setup_view(&mut self, ui: &mut Ui) {
        ui.heading("First diagnostic check");
        ui.label("Review local setup and exact incident context before choosing any live read-only check.");
        ui.small("Opening this page and following its links run no check or connection and change no Windows setting.");
        ui.add_space(12.0);
        let snapshot = self.intelligence.diagnostic.setup_snapshot();
        let profile = self.selected_profile();
        let checks = assess(profile, &snapshot, local_powershell_present());
        for check in checks {
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(check.title);
                    let color = match check.status {
                        Status::Ready => tw::BLUE_700,
                        Status::NeedsInput => tw::RED_600,
                        Status::Unknown => tw::SLATE_700,
                    };
                    ui.label(RichText::new(check.status.label()).color(color));
                });
                ui.label(check.detail);
                if let Some((view, label)) = check.next {
                    if ui.button(label).clicked() {
                        self.view = view;
                    }
                }
            });
            ui.add_space(5.0);
        }
        ui.separator();
        ui.label("New diagnostic cases start in simulation unless you explicitly choose read-only. A review and approval are required before each live check.");
        if ui
            .button("Open Diagnostic Lab to prepare or review …")
            .clicked()
        {
            self.view = View::Intelligence;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic_lab::Config;
    use chrono::Utc;

    fn snapshot() -> Snapshot {
        Snapshot {
            incident: "Application unreachable".into(),
            service: "RealService".into(),
            application: "https://app.contoso.com/".into(),
            dependency: "https://api.contoso.com/health".into(),
            mode: Mode::Simulation,
            source: None,
            selected_case: None,
            store_error: false,
            awaiting_approval: false,
            running: false,
        }
    }

    fn status<'a>(checks: &'a [Item], title: &str) -> &'a Item {
        checks.iter().find(|item| item.title == title).unwrap()
    }

    #[test]
    fn no_profile_or_tool_does_not_claim_remote_readiness() {
        let checks = assess(None, &snapshot(), false);
        assert_eq!(
            status(&checks, "Saved Windows target").status,
            Status::NeedsInput
        );
        assert_eq!(
            status(&checks, "Local transport tool").status,
            Status::NeedsInput
        );
        assert_eq!(
            status(&checks, "Diagnostic evidence").status,
            Status::Unknown
        );
        assert_eq!(
            status(&checks, "Functional verification").status,
            Status::Unknown
        );
    }

    #[test]
    fn direct_rdp_is_only_configuration_evidence() {
        let profile = ConnectionProfile::sample("Lab", "server.contoso.com", "Test", false);
        let checks = assess(Some(&profile), &snapshot(), true);
        assert_eq!(
            status(&checks, "Saved Windows target").status,
            Status::Ready
        );
        assert_eq!(
            status(&checks, "Authentication identity").status,
            Status::Unknown
        );
        assert_eq!(
            status(&checks, "Diagnostic mode and saved case").status,
            Status::NeedsInput
        );
        assert_eq!(
            status(&checks, "Read-only approval").status,
            Status::Unknown
        );
    }

    #[test]
    fn gateway_non_rdp_and_reserved_values_cannot_qualify() {
        let mut profile = ConnectionProfile::sample("Lab", "server.contoso.com", "Test", false);
        profile.options.gateway.enabled = true;
        assert_eq!(
            status(
                &assess(Some(&profile), &snapshot(), true),
                "Saved Windows target"
            )
            .status,
            Status::NeedsInput
        );
        profile.options.gateway.enabled = false;
        profile.protocol = Protocol::Ssh;
        assert_eq!(
            status(
                &assess(Some(&profile), &snapshot(), true),
                "Saved Windows target"
            )
            .status,
            Status::NeedsInput
        );
        profile.protocol = Protocol::Rdp;
        profile.host = "fixture.invalid".into();
        assert_eq!(
            status(
                &assess(Some(&profile), &snapshot(), true),
                "Saved Windows target"
            )
            .status,
            Status::NeedsInput
        );
        let mut inputs = snapshot();
        inputs.application = "https://app.example.com/".into();
        inputs.dependency = "https://api.example.invalid/health".into();
        let checks = assess(Some(&profile), &inputs, true);
        assert_eq!(
            status(&checks, "Application URL").status,
            Status::NeedsInput
        );
        assert_eq!(status(&checks, "Dependency URL").status, Status::NeedsInput);
    }

    #[test]
    fn simulated_or_unreadable_case_never_supplies_live_evidence() {
        let profile = ConnectionProfile::sample("Lab", "server.contoso.com", "Test", false);
        let mut inputs = snapshot();
        inputs.store_error = true;
        let checks = assess(Some(&profile), &inputs, true);
        assert_eq!(
            status(&checks, "Diagnostic evidence").status,
            Status::Unknown
        );
        assert!(status(&checks, "Diagnostic evidence")
            .detail
            .contains("could not be read"));
        assert_eq!(
            status(&checks, "Diagnostic mode and saved case").status,
            Status::NeedsInput
        );
    }

    #[test]
    fn changed_profile_invalidates_incident_and_saved_case() {
        let profile = ConnectionProfile::sample("Lab", "server.contoso.com", "Test", false);
        let target = Target::from_profile(&profile);
        let source = Source {
            record_id: "failure-1".into(),
            profile_id: profile.id,
            endpoint: crate::incident::endpoint_key(&target),
            observed_at: Utc::now(),
            title: "Application unreachable".into(),
            evidence: vec!["Observed failure".into()],
        };
        let case = Case::new(
            Config {
                mode: Mode::ReadOnly,
                scenario: None,
                target: Some(target),
                incident: "Application unreachable".into(),
                service: "RealService".into(),
                application: "https://app.contoso.com/".into(),
                dependency: "https://api.contoso.com/health".into(),
            },
            Utc::now(),
        )
        .unwrap();
        let mut inputs = snapshot();
        inputs.mode = Mode::ReadOnly;
        inputs.source = Some(source);
        inputs.selected_case = Some(case);
        let checks = assess(Some(&profile), &inputs, true);
        assert_eq!(status(&checks, "Incident handoff").status, Status::Ready);
        assert_eq!(
            status(&checks, "Diagnostic mode and saved case").status,
            Status::Ready
        );

        inputs.selected_case.as_mut().unwrap().config.application =
            "https://app.example.invalid/".into();
        let checks = assess(Some(&profile), &inputs, true);
        assert_eq!(
            status(&checks, "Diagnostic mode and saved case").status,
            Status::NeedsInput
        );
        inputs.selected_case.as_mut().unwrap().config.application =
            "https://app.contoso.com/".into();

        let mut changed = profile;
        changed.host = "other.contoso.com".into();
        let checks = assess(Some(&changed), &inputs, true);
        assert_eq!(
            status(&checks, "Incident handoff").status,
            Status::NeedsInput
        );
        assert_eq!(
            status(&checks, "Diagnostic mode and saved case").status,
            Status::NeedsInput
        );
        assert_eq!(
            status(&checks, "Diagnostic evidence").status,
            Status::Unknown
        );
    }
}
