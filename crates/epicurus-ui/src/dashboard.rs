//! The egui dashboard: overview, incidents, decoy map, allowlist, alert
//! channels and settings. It runs unprivileged and talks to the service only
//! through the IPC worker.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use epicurus_core::allowlist::AllowEntry;
use epicurus_core::catalog::Category;
use epicurus_core::config::{PolicyAction, SensorMode, Theme};
use epicurus_core::incident::{ActionKind, Incident, IncidentStatus, IncidentSummary};
use epicurus_core::ipc::{
    AlertUpdate, AlertsView, ChannelKind, ManifestView, PlanSummary, ProtectionState, Request,
    Response, SettingsUpdate, SettingsView, StatusInfo,
};
use epicurus_core::scoring::Severity;
use epicurus_core::timefmt::rfc3339;

use crate::client::{Verifier, Worker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Incidents,
    Decoys,
    Allowlist,
    Alerts,
    Settings,
}

impl Tab {
    const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Incidents,
        Tab::Decoys,
        Tab::Allowlist,
        Tab::Alerts,
        Tab::Settings,
    ];
    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Incidents => "Incidents",
            Tab::Decoys => "Decoy map",
            Tab::Allowlist => "Allowlist",
            Tab::Alerts => "Alert channels",
            Tab::Settings => "Settings",
        }
    }
}

#[derive(Default)]
struct AlertForm {
    discord_url: String,
    slack_url: String,
    ntfy_server: String,
    ntfy_topic: String,
    ntfy_token: String,
    generic_url: String,
    generic_secret: String,
    results: BTreeMap<String, String>,
}

/// Dashboard state.
pub struct Dashboard {
    worker: Worker,
    tab: Tab,
    status: Option<StatusInfo>,
    error: Option<String>,
    incidents: Vec<IncidentSummary>,
    selected: Option<Incident>,
    pending_select: Option<String>,
    manifest: Option<ManifestView>,
    plan: Option<PlanSummary>,
    allow_user: Vec<AllowEntry>,
    allow_builtin: Vec<AllowEntry>,
    allow_dirty: bool,
    alerts: Option<AlertsView>,
    alert_form: AlertForm,
    settings: Option<SettingsView>,
    theme: Theme,
    toast_msg: Option<(String, Instant)>,
    last_poll: Instant,
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => Color32::from_rgb(0xE5, 0x48, 0x4D),
        Severity::High => Color32::from_rgb(0xF7, 0x6B, 0x15),
        Severity::Medium => Color32::from_rgb(0xFF, 0xB2, 0x24),
        Severity::Low => Color32::from_rgb(0x3E, 0x9B, 0xFF),
        Severity::Info => Color32::from_rgb(0x8B, 0x95, 0xA5),
    }
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color)
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text.to_uppercase())
                    .color(Color32::WHITE)
                    .strong()
                    .size(11.0),
            );
        });
}

fn card(ui: &mut egui::Ui, title: &str, value: &str, sub: &str) {
    egui::Frame::group(ui.style())
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_min_width(190.0);
            ui.label(RichText::new(title).small().weak());
            ui.label(RichText::new(value).size(22.0).strong());
            if !sub.is_empty() {
                ui.label(RichText::new(sub).small().weak());
            }
        });
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

impl Dashboard {
    /// Creates the dashboard and kicks off the initial requests.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        pipe: String,
        verifier: Verifier,
        incident: Option<String>,
    ) -> Self {
        let ctx = cc.egui_ctx.clone();
        let worker = Worker::spawn(pipe, verifier, move || ctx.request_repaint());
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        let s = Self {
            worker,
            tab: if incident.is_some() {
                Tab::Incidents
            } else {
                Tab::Overview
            },
            status: None,
            error: None,
            incidents: Vec::new(),
            selected: None,
            pending_select: incident,
            manifest: None,
            plan: None,
            allow_user: Vec::new(),
            allow_builtin: Vec::new(),
            allow_dirty: false,
            alerts: None,
            alert_form: AlertForm {
                ntfy_server: "https://ntfy.sh".into(),
                ..Default::default()
            },
            settings: None,
            theme: Theme::Dark,
            toast_msg: None,
            last_poll: Instant::now() - Duration::from_secs(60),
        };
        s.worker.send("settings", Request::GetSettings);
        if let Some(id) = s.pending_select.clone() {
            s.worker.send("incident", Request::GetIncident { id });
        }
        s
    }

    fn flash(&mut self, msg: impl Into<String>) {
        self.toast_msg = Some((msg.into(), Instant::now()));
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if self.last_poll.elapsed() >= Duration::from_secs(2) {
            self.last_poll = Instant::now();
            self.worker.send("status", Request::Status);
            match self.tab {
                Tab::Incidents => self
                    .worker
                    .send("incidents", Request::ListIncidents { limit: 200 }),
                Tab::Decoys if self.manifest.is_none() => {
                    self.worker.send("manifest", Request::GetManifest)
                }
                Tab::Allowlist if self.allow_builtin.is_empty() => {
                    self.worker.send("allowlist", Request::GetAllowlist)
                }
                Tab::Alerts if self.alerts.is_none() => {
                    self.worker.send("alerts", Request::GetAlerts)
                }
                _ => {}
            }
        }
        for a in self.worker.poll() {
            match (a.tag, a.result) {
                (_, Err(e)) => self.error = Some(e),
                ("status", Ok(Response::Status(s))) => {
                    self.error = None;
                    self.status = Some(s);
                }
                ("incidents", Ok(Response::Incidents { items })) => self.incidents = items,
                ("incident", Ok(Response::Incident { incident })) => {
                    self.selected = Some(*incident)
                }
                ("manifest", Ok(Response::Manifest(m))) => self.manifest = Some(m),
                ("allowlist", Ok(Response::Allowlist { entries, builtin })) => {
                    self.allow_user = entries;
                    self.allow_builtin = builtin;
                    self.allow_dirty = false;
                }
                ("alerts", Ok(Response::Alerts(v))) => {
                    if let Some(s) = &v.ntfy.extra {
                        self.alert_form.ntfy_server = s.clone();
                    }
                    self.alerts = Some(v);
                }
                ("settings", Ok(Response::Settings(v))) => {
                    self.theme = v.theme;
                    ctx.set_theme(match v.theme {
                        Theme::Dark => egui::Theme::Dark,
                        Theme::Light => egui::Theme::Light,
                    });
                    self.settings = Some(v);
                }
                ("plan", Ok(Response::Plan(p))) => {
                    let n = p.planned.len();
                    self.plan = Some(p);
                    self.flash(format!("{n} decoy(s) in plan"));
                    self.manifest = None;
                }
                ("unplant", Ok(Response::Unplant(r))) => {
                    self.flash(format!(
                        "Removed {} file(s); kept {} modified",
                        r.removed.len(),
                        r.kept_modified.len()
                    ));
                    self.manifest = None;
                }
                ("action", Ok(Response::ActionResult { ok, detail })) => {
                    self.flash(if ok {
                        detail
                    } else {
                        format!("Failed: {detail}")
                    });
                    if let Some(id) = self.selected.as_ref().map(|i| i.id.clone()) {
                        self.worker.send("incident", Request::GetIncident { id });
                    }
                }
                (tag, Ok(Response::ActionResult { ok, detail })) if tag.starts_with("test:") => {
                    self.alert_form.results.insert(
                        tag.trim_start_matches("test:").to_string(),
                        format!("{}: {detail}", if ok { "OK" } else { "Failed" }),
                    );
                }
                ("ack", Ok(_)) => self.flash("Saved"),
                _ => {}
            }
        }
        ctx.request_repaint_after(Duration::from_secs(2));
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Epicurus").size(18.0).strong());
            ui.separator();
            match (&self.status, &self.error) {
                (Some(s), None) => {
                    let (text, color) = match s.protection {
                        ProtectionState::Protected => {
                            ("Protected", Color32::from_rgb(0x30, 0xA4, 0x6C))
                        }
                        ProtectionState::Degraded => {
                            ("Degraded", Color32::from_rgb(0xF5, 0xA5, 0x24))
                        }
                        ProtectionState::Unprotected => {
                            ("Unprotected", Color32::from_rgb(0xE5, 0x48, 0x4D))
                        }
                    };
                    badge(ui, text, color);
                    if !s.pending.is_empty() {
                        badge(
                            ui,
                            &format!("{} awaiting decision", s.pending.len()),
                            severity_color(Severity::Critical),
                        );
                    }
                }
                (_, Some(e)) => {
                    badge(
                        ui,
                        "Service unreachable",
                        Color32::from_rgb(0x8B, 0x95, 0xA5),
                    );
                    ui.label(RichText::new(e).weak().small());
                }
                _ => {
                    ui.spinner();
                }
            }
            if let Some((msg, at)) = &self.toast_msg
                && at.elapsed() < Duration::from_secs(6)
            {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(msg).italics());
                });
            }
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        for t in Tab::ALL {
            if ui
                .selectable_label(self.tab == t, RichText::new(t.label()).size(14.0))
                .clicked()
                && self.tab != t
            {
                self.tab = t;
                self.last_poll = Instant::now() - Duration::from_secs(60);
                match t {
                    Tab::Decoys => self.worker.send("manifest", Request::GetManifest),
                    Tab::Allowlist => self.worker.send("allowlist", Request::GetAllowlist),
                    Tab::Alerts => self.worker.send("alerts", Request::GetAlerts),
                    Tab::Settings => self.worker.send("settings", Request::GetSettings),
                    _ => {}
                }
            }
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.label(
                RichText::new(format!("v{}", epicurus_core::VERSION))
                    .small()
                    .weak(),
            );
        });
    }

    fn incident_row(&mut self, ui: &mut egui::Ui, s: &IncidentSummary) {
        ui.horizontal(|ui| {
            badge(ui, s.severity.as_str(), severity_color(s.severity));
            ui.label(RichText::new(format!("{:>3}", s.score)).monospace());
            let label = format!(
                "{} (PID {})  {} decoy(s){}",
                file_name(&s.image),
                s.pid,
                s.decoys,
                if s.simulated { "  [simulation]" } else { "" }
            );
            let selected = self.selected.as_ref().is_some_and(|i| i.id == s.id);
            if ui.selectable_label(selected, label).clicked() {
                self.worker
                    .send("incident", Request::GetIncident { id: s.id.clone() });
                self.tab = Tab::Incidents;
            }
            ui.label(RichText::new(rfc3339(s.created_at)).weak().small());
            if s.status == IncidentStatus::AwaitingDecision {
                ui.label(RichText::new("suspended").color(severity_color(Severity::High)));
            }
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let Some(s) = self.status.clone() else {
            ui.label("Waiting for the service...");
            return;
        };
        ui.heading("Overview");
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let prot = match s.protection {
                ProtectionState::Protected => "Protected",
                ProtectionState::Degraded => "Degraded",
                ProtectionState::Unprotected => "Unprotected",
            };
            card(
                ui,
                "Protection",
                prot,
                &format!("file sensor: {}", s.sensor.mode),
            );
            card(
                ui,
                "Sensors",
                &format!(
                    "{}/{} oplocks",
                    s.sensor.oplocks_armed, s.sensor.oplocks_total
                ),
                &format!(
                    "{} dirs watched, {} lost events",
                    s.sensor.integrity_watchers,
                    s.sensor.events_lost + s.sensor.buffers_lost
                ),
            );
            card(
                ui,
                "Decoys planted",
                &s.decoys_planted.to_string(),
                &format!("{} categories", s.decoys_by_category.len()),
            );
            card(
                ui,
                "Touches (24h)",
                &s.touches_24h.to_string(),
                &format!("{} incident(s)", s.incidents_24h),
            );
        });
        if !s.sensor.problems.is_empty() {
            ui.add_space(8.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(RichText::new("Sensor problems").strong());
                for p in s.sensor.problems.iter().rev().take(5) {
                    ui.label(RichText::new(p).color(Color32::from_rgb(0xF5, 0xA5, 0x24)));
                }
            });
        }
        if !s.pending.is_empty() {
            ui.add_space(12.0);
            ui.label(RichText::new("Awaiting your decision").strong().size(15.0));
            for p in &s.pending {
                ui.horizontal(|ui| {
                    self.incident_row(ui, p);
                    if ui.button("Kill tree").clicked() {
                        self.worker.send(
                            "action",
                            Request::IncidentAction {
                                id: p.id.clone(),
                                action: ActionKind::KillTree,
                            },
                        );
                    }
                    if ui.button("Resume").clicked() {
                        self.worker.send(
                            "action",
                            Request::IncidentAction {
                                id: p.id.clone(),
                                action: ActionKind::Resume,
                            },
                        );
                    }
                });
            }
        }
        ui.add_space(12.0);
        ui.label(RichText::new("Recent incidents").strong().size(15.0));
        if s.recent.is_empty() {
            ui.label(
                RichText::new(
                    "No incidents. Run `epicurus simulate` to verify detection end to end.",
                )
                .weak(),
            );
        }
        for r in &s.recent {
            self.incident_row(ui, r);
        }
    }

    fn incidents(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("incident-list")
            .resizable(true)
            .default_size(420.0)
            .show(ui, |ui| {
                ui.heading("Incidents");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let list = self.incidents.clone();
                    if list.is_empty() {
                        ui.label(RichText::new("No incidents yet.").weak());
                    }
                    for s in &list {
                        self.incident_row(ui, s);
                    }
                });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.selected.clone() {
                None => {
                    ui.label(RichText::new("Select an incident.").weak());
                }
                Some(inc) => self.incident_detail(ui, &inc),
            });
        });
    }

    fn incident_detail(&mut self, ui: &mut egui::Ui, inc: &Incident) {
        let p = &inc.process;
        ui.horizontal(|ui| {
            badge(ui, inc.severity.as_str(), severity_color(inc.severity));
            ui.label(
                RichText::new(format!("{}/100", inc.score))
                    .size(18.0)
                    .strong(),
            );
            ui.label(RichText::new(&inc.id).monospace().weak());
            if inc.simulated {
                badge(ui, "simulation", Color32::from_rgb(0xFF, 0xB2, 0x24));
            }
        });
        ui.label(RichText::new(format!("{} (PID {})", p.image_path, p.pid)).monospace());
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let id = inc.id.clone();
            let act = |ui: &mut egui::Ui, label: &str, action: ActionKind, enabled: bool| {
                if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                    self.worker.send(
                        "action",
                        Request::IncidentAction {
                            id: id.clone(),
                            action,
                        },
                    );
                }
            };
            let live = inc.status != IncidentStatus::Resolved && p.pid != 0;
            act(ui, "Kill tree", ActionKind::KillTree, live);
            act(
                ui,
                "Resume",
                ActionKind::Resume,
                inc.status == IncidentStatus::AwaitingDecision,
            );
            act(
                ui,
                "Quarantine",
                ActionKind::Quarantine,
                live && p.image_sha256.is_some(),
            );
            act(
                ui,
                "Block network",
                ActionKind::BlockNetwork,
                !p.image_path.is_empty() && p.pid != 0,
            );
            act(ui, "Allowlist", ActionKind::Allowlist, live);
            act(
                ui,
                "Dismiss",
                ActionKind::Dismiss,
                inc.status == IncidentStatus::Open,
            );
            if ui.button("Export report").clicked() {
                match export(inc) {
                    Ok(dir) => self.flash(format!("Exported to {}", dir.display())),
                    Err(e) => self.flash(format!("Export failed: {e}")),
                }
            }
        });
        ui.add_space(8.0);
        egui::CollapsingHeader::new(RichText::new("Why this score").strong())
            .default_open(true)
            .show(ui, |ui| {
                for r in &inc.reasons {
                    ui.horizontal(|ui| {
                        let color = if r.points > 0 {
                            severity_color(Severity::Critical)
                        } else if r.points < 0 {
                            Color32::from_rgb(0x30, 0xA4, 0x6C)
                        } else {
                            ui.visuals().weak_text_color()
                        };
                        ui.label(
                            RichText::new(format!("{:+4}", r.points))
                                .monospace()
                                .color(color),
                        );
                        ui.label(&r.detail);
                    });
                }
            });
        egui::CollapsingHeader::new(RichText::new("Process").strong())
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("proc")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        let mut row = |k: &str, v: String| {
                            ui.label(RichText::new(k).weak());
                            ui.label(RichText::new(v).monospace());
                            ui.end_row();
                        };
                        row(
                            "SHA-256",
                            p.image_sha256.clone().unwrap_or_else(|| "unknown".into()),
                        );
                        row(
                            "Signature",
                            format!(
                                "{:?}{}",
                                p.signature.status,
                                if p.signature.catalog_signed {
                                    " (catalog)"
                                } else {
                                    ""
                                }
                            ),
                        );
                        row(
                            "Signer chain",
                            if p.signature.chain.is_empty() {
                                "none".into()
                            } else {
                                p.signature.chain.join(" > ")
                            },
                        );
                        row("Command line", p.command_line.clone().unwrap_or_default());
                        row(
                            "User",
                            format!(
                                "{} ({})",
                                p.user.clone().unwrap_or_default(),
                                p.integrity.clone().unwrap_or_default()
                            ),
                        );
                        row("Started", p.start_time.map(rfc3339).unwrap_or_default());
                        row(
                            "Image created",
                            p.image_created.map(rfc3339).unwrap_or_default(),
                        );
                        row(
                            "Status",
                            format!(
                                "{:?}{}",
                                inc.status,
                                if p.exited {
                                    ", exited before triage"
                                } else {
                                    ""
                                }
                            ),
                        );
                    });
            });
        egui::CollapsingHeader::new(RichText::new("Process tree").strong())
            .default_open(true)
            .show(ui, |ui| {
                for n in &inc.tree {
                    let prefix = match n.role.as_str() {
                        "subject" => "> ",
                        "child" => "    - ",
                        _ => "",
                    };
                    let text = format!("{prefix}{} ({})", file_name(&n.image), n.pid);
                    let rt = RichText::new(text).monospace();
                    ui.label(if n.role == "subject" { rt.strong() } else { rt })
                        .on_hover_text(n.command_line.clone().unwrap_or_default());
                }
            });
        egui::CollapsingHeader::new(
            RichText::new(format!("Decoys touched ({})", inc.touches.len())).strong(),
        )
        .default_open(true)
        .show(ui, |ui| {
            for t in &inc.touches {
                ui.label(
                    RichText::new(format!(
                        "{}  {:?}  {}  [{:?}]",
                        rfc3339(t.at),
                        t.op,
                        t.decoy_id,
                        t.source
                    ))
                    .monospace(),
                )
                .on_hover_text(&t.path);
            }
        });
        if !inc.related_paths.is_empty() {
            egui::CollapsingHeader::new(
                RichText::new("Real credential stores also opened").strong(),
            )
            .show(ui, |ui| {
                for r in &inc.related_paths {
                    ui.label(RichText::new(r).monospace());
                }
            });
        }
        egui::CollapsingHeader::new(
            RichText::new(format!("Network ({})", p.network.len())).strong(),
        )
        .show(ui, |ui| {
            for c in &p.network {
                ui.label(
                    RichText::new(format!(
                        "{:5} {} -> {} {}",
                        c.protocol, c.local, c.remote, c.state
                    ))
                    .monospace(),
                );
            }
        });
        egui::CollapsingHeader::new(RichText::new("Timeline").strong())
            .default_open(true)
            .show(ui, |ui| {
                for e in &inc.timeline {
                    ui.label(
                        RichText::new(format!("{}  {:8}  {}", rfc3339(e.at), e.kind, e.message))
                            .monospace(),
                    );
                }
            });
    }

    fn decoys(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decoy map");
        ui.horizontal(|ui| {
            if ui.button("Re-plant missing").clicked() {
                self.worker.send("plan", Request::Replant);
            }
            if ui.button("Preview plan (dry run)").clicked() {
                self.worker.send(
                    "plan",
                    Request::Plant {
                        profile: None,
                        dry_run: true,
                    },
                );
            }
            if ui.button("Refresh").clicked() {
                self.worker.send("manifest", Request::GetManifest);
            }
        });
        let Some(m) = self.manifest.clone() else {
            ui.spinner();
            return;
        };
        ui.label(
            RichText::new(format!(
                "Profile \"{}\" - {} file(s) planted",
                m.profile,
                m.entries.len()
            ))
            .weak(),
        );
        egui::ScrollArea::vertical().show(ui, |ui| {
            for cat in Category::ALL {
                let files: Vec<_> = m.entries.iter().filter(|e| e.category == cat).collect();
                let mut enabled = m.enabled.contains(&cat);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .checkbox(&mut enabled, RichText::new(cat.label()).strong())
                        .changed()
                    {
                        self.worker.send(
                            "plan_or_unplant",
                            Request::SetCategory {
                                category: cat,
                                enabled,
                            },
                        );
                        self.manifest = None;
                    }
                    ui.label(RichText::new(format!("{} file(s)", files.len())).weak());
                });
                for f in files {
                    ui.horizontal(|ui| {
                        ui.add_space(24.0);
                        ui.label(
                            RichText::new(f.path.display().to_string())
                                .monospace()
                                .small(),
                        )
                        .on_hover_text(format!(
                            "decoy {}\nSHA-256 {}\nplanted {}{}",
                            f.decoy_id,
                            f.sha256,
                            rfc3339(f.planted_at),
                            if f.canary { "\nlive canary" } else { "" }
                        ));
                    });
                }
            }
            if let Some(p) = &self.plan {
                ui.add_space(12.0);
                egui::CollapsingHeader::new(RichText::new("Last plan").strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        for it in &p.planned {
                            ui.label(
                                RichText::new(format!(
                                    "+ {}  {}{}",
                                    it.decoy_id,
                                    it.target,
                                    if it.alternate { "  (alternate)" } else { "" }
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                        for s in &p.skipped {
                            ui.label(
                                RichText::new(format!("- {}  {}", s.decoy_id, s.reason))
                                    .monospace()
                                    .small()
                                    .weak(),
                            );
                        }
                        for e in &p.errors {
                            ui.label(
                                RichText::new(format!("! {e}"))
                                    .color(severity_color(Severity::Critical)),
                            );
                        }
                    });
            }
        });
    }

    fn allowlist(&mut self, ui: &mut egui::Ui) {
        ui.heading("Allowlist");
        ui.label(RichText::new("Entries match a valid Authenticode signer plus an image path pattern, or a SHA-256. Process names alone never match.").weak());
        ui.add_space(6.0);
        let mut remove = None;
        egui::ScrollArea::vertical()
            .max_height(360.0)
            .show(ui, |ui| {
                egui::Grid::new("allow")
                    .num_columns(5)
                    .striped(true)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Name").strong());
                        ui.label(RichText::new("Signers (comma separated)").strong());
                        ui.label(RichText::new("Path pattern").strong());
                        ui.label(RichText::new("SHA-256 (optional)").strong());
                        ui.label("");
                        ui.end_row();
                        for (i, e) in self.allow_user.iter_mut().enumerate() {
                            let mut signers = e.signers.join(", ");
                            let mut sha = e.sha256.clone().unwrap_or_default();
                            let mut changed = ui.text_edit_singleline(&mut e.name).changed();
                            if ui.text_edit_singleline(&mut signers).changed() {
                                e.signers = signers
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                changed = true;
                            }
                            changed |= ui
                                .add(egui::TextEdit::singleline(&mut e.path).desired_width(320.0))
                                .changed();
                            if ui.text_edit_singleline(&mut sha).changed() {
                                e.sha256 =
                                    (!sha.trim().is_empty()).then(|| sha.trim().to_lowercase());
                                changed = true;
                            }
                            if ui.button("Remove").clicked() {
                                remove = Some(i);
                            }
                            if changed {
                                self.allow_dirty = true;
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(i) = remove {
            self.allow_user.remove(i);
            self.allow_dirty = true;
        }
        ui.horizontal(|ui| {
            if ui.button("Add entry").clicked() {
                self.allow_user.push(AllowEntry {
                    name: "New entry".into(),
                    signers: vec![],
                    path: String::new(),
                    sha256: None,
                });
                self.allow_dirty = true;
            }
            let invalid: Vec<String> = self
                .allow_user
                .iter()
                .filter_map(|e| e.validate().err().map(|x| x.to_string()))
                .collect();
            if ui
                .add_enabled(
                    self.allow_dirty && invalid.is_empty(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                self.worker.send(
                    "ack",
                    Request::SetAllowlist {
                        entries: self.allow_user.clone(),
                    },
                );
                self.allow_dirty = false;
            }
            if let Some(first) = invalid.first() {
                ui.label(RichText::new(first).color(severity_color(Severity::High)));
            }
        });
        ui.add_space(12.0);
        egui::CollapsingHeader::new(
            RichText::new(format!("Built-in entries ({})", self.allow_builtin.len())).strong(),
        )
        .show(ui, |ui| {
            for e in &self.allow_builtin {
                ui.label(
                    RichText::new(format!(
                        "{}: {} @ {}",
                        e.name,
                        e.signers.join(" | "),
                        e.path
                    ))
                    .monospace()
                    .small(),
                );
            }
        });
    }

    fn alerts(&mut self, ui: &mut egui::Ui) {
        ui.heading("Alert channels");
        let Some(v) = self.alerts.clone() else {
            ui.spinner();
            return;
        };
        ui.label(RichText::new("Webhook URLs, topics and keys are encrypted with DPAPI by the service and never shown again.").weak());
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Minimum severity:");
            let mut sev = v.min_severity;
            egui::ComboBox::from_id_salt("minsev")
                .selected_text(sev.as_str())
                .show_ui(ui, |ui| {
                    for s in Severity::ALL {
                        ui.selectable_value(&mut sev, s, s.as_str());
                    }
                });
            if sev != v.min_severity {
                self.worker.send(
                    "alerts",
                    Request::SetAlertChannel {
                        update: AlertUpdate::MinSeverity { severity: sev },
                    },
                );
            }
        });
        let send_test = |w: &Worker, ch: ChannelKind, tag: &'static str| {
            w.send(tag, Request::TestAlert { channel: ch })
        };
        let result = |ui: &mut egui::Ui, form: &AlertForm, key: &str| {
            if let Some(r) = form.results.get(key) {
                ui.label(RichText::new(r).small());
            }
        };

        ui.add_space(8.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let mut t = v.toast;
                if ui
                    .checkbox(&mut t, "Windows toast (with Kill / Resume / Open)")
                    .changed()
                {
                    self.worker.send(
                        "alerts",
                        Request::SetAlertChannel {
                            update: AlertUpdate::Toast { enabled: t },
                        },
                    );
                }
                if ui.button("Send test").clicked() {
                    send_test(&self.worker, ChannelKind::Toast, "test:toast");
                }
                result(ui, &self.alert_form, "toast");
            });
            ui.horizontal(|ui| {
                let mut e = v.eventlog;
                if ui
                    .checkbox(&mut e, "Windows Event Log (source \"Epicurus\")")
                    .changed()
                {
                    self.worker.send(
                        "alerts",
                        Request::SetAlertChannel {
                            update: AlertUpdate::EventLog { enabled: e },
                        },
                    );
                }
                if ui.button("Send test").clicked() {
                    send_test(&self.worker, ChannelKind::EventLog, "test:eventlog");
                }
                result(ui, &self.alert_form, "eventlog");
            });
        });

        let webhook = |ui: &mut egui::Ui,
                       title: &str,
                       view: &epicurus_core::ipc::ChannelView,
                       url: &mut String,
                       kind: ChannelKind,
                       tag: &'static str,
                       key: &str,
                       worker: &Worker,
                       results: &BTreeMap<String, String>| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).strong());
                    ui.label(
                        RichText::new(if view.configured {
                            "configured"
                        } else {
                            "not configured"
                        })
                        .weak(),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(url)
                            .password(true)
                            .hint_text("paste a new URL to replace the stored one")
                            .desired_width(420.0),
                    );
                    let mut enabled = view.enabled;
                    let toggled = ui.checkbox(&mut enabled, "Enabled").changed();
                    if ui.button("Save").clicked() || toggled {
                        let u = (!url.trim().is_empty()).then(|| url.trim().to_string());
                        let update = match kind {
                            ChannelKind::Discord => AlertUpdate::Discord { enabled, url: u },
                            _ => AlertUpdate::Slack { enabled, url: u },
                        };
                        worker.send("alerts", Request::SetAlertChannel { update });
                        url.clear();
                    }
                    if ui
                        .add_enabled(view.configured, egui::Button::new("Send test"))
                        .clicked()
                    {
                        worker.send(tag, Request::TestAlert { channel: kind });
                    }
                    if let Some(r) = results.get(key) {
                        ui.label(RichText::new(r).small());
                    }
                });
            });
        };
        ui.add_space(6.0);
        let results = self.alert_form.results.clone();
        webhook(
            ui,
            "Discord webhook",
            &v.discord,
            &mut self.alert_form.discord_url,
            ChannelKind::Discord,
            "test:discord",
            "discord",
            &self.worker,
            &results,
        );
        webhook(
            ui,
            "Slack webhook",
            &v.slack,
            &mut self.alert_form.slack_url,
            ChannelKind::Slack,
            "test:slack",
            "slack",
            &self.worker,
            &results,
        );

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("ntfy").strong());
                ui.label(
                    RichText::new(if v.ntfy.configured {
                        "configured"
                    } else {
                        "not configured"
                    })
                    .weak(),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Server");
                ui.text_edit_singleline(&mut self.alert_form.ntfy_server);
                ui.label("Topic");
                ui.add(
                    egui::TextEdit::singleline(&mut self.alert_form.ntfy_topic)
                        .password(true)
                        .desired_width(160.0),
                );
                ui.label("Token");
                ui.add(
                    egui::TextEdit::singleline(&mut self.alert_form.ntfy_token)
                        .password(true)
                        .desired_width(160.0),
                );
            });
            ui.horizontal(|ui| {
                let mut enabled = v.ntfy.enabled;
                let toggled = ui.checkbox(&mut enabled, "Enabled").changed();
                if ui.button("Save").clicked() || toggled {
                    let f = &mut self.alert_form;
                    self.worker.send(
                        "alerts",
                        Request::SetAlertChannel {
                            update: AlertUpdate::Ntfy {
                                enabled,
                                server: Some(f.ntfy_server.trim().to_string()),
                                topic: (!f.ntfy_topic.trim().is_empty())
                                    .then(|| f.ntfy_topic.trim().to_string()),
                                token: (!f.ntfy_token.trim().is_empty())
                                    .then(|| f.ntfy_token.trim().to_string()),
                            },
                        },
                    );
                    f.ntfy_topic.clear();
                    f.ntfy_token.clear();
                }
                if ui
                    .add_enabled(v.ntfy.configured, egui::Button::new("Send test"))
                    .clicked()
                {
                    send_test(&self.worker, ChannelKind::Ntfy, "test:ntfy");
                }
                result(ui, &self.alert_form, "ntfy");
            });
        });

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Generic JSON webhook").strong());
                ui.label(
                    RichText::new(format!(
                        "{}; {}",
                        if v.generic.configured {
                            "configured"
                        } else {
                            "not configured"
                        },
                        v.generic.extra.clone().unwrap_or_default()
                    ))
                    .weak(),
                );
            });
            ui.horizontal(|ui| {
                ui.label("URL");
                ui.add(
                    egui::TextEdit::singleline(&mut self.alert_form.generic_url)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.label("HMAC secret");
                ui.add(
                    egui::TextEdit::singleline(&mut self.alert_form.generic_secret)
                        .password(true)
                        .desired_width(200.0),
                );
            });
            ui.horizontal(|ui| {
                let mut enabled = v.generic.enabled;
                let toggled = ui.checkbox(&mut enabled, "Enabled").changed();
                if ui.button("Save").clicked() || toggled {
                    let f = &mut self.alert_form;
                    self.worker.send(
                        "alerts",
                        Request::SetAlertChannel {
                            update: AlertUpdate::Generic {
                                enabled,
                                url: (!f.generic_url.trim().is_empty())
                                    .then(|| f.generic_url.trim().to_string()),
                                secret: (!f.generic_secret.is_empty())
                                    .then(|| f.generic_secret.clone()),
                            },
                        },
                    );
                    f.generic_url.clear();
                    f.generic_secret.clear();
                }
                if ui
                    .add_enabled(v.generic.configured, egui::Button::new("Send test"))
                    .clicked()
                {
                    send_test(&self.worker, ChannelKind::Generic, "test:generic");
                }
                result(ui, &self.alert_form, "generic");
            });
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        let Some(v) = self.settings.clone() else {
            ui.spinner();
            return;
        };
        let mut update = SettingsUpdate::default();
        egui::Grid::new("settings").num_columns(2).spacing([24.0, 10.0]).show(ui, |ui| {
            ui.label("Theme");
            let mut theme = v.theme;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut theme, Theme::Dark, "Dark");
                ui.selectable_value(&mut theme, Theme::Light, "Light");
            });
            if theme != v.theme {
                update.theme = Some(theme);
            }
            ui.end_row();

            ui.label("Decoy profile");
            let mut profile = v.profile.clone();
            egui::ComboBox::from_id_salt("profile").selected_text(&profile).show_ui(ui, |ui| {
                for p in &v.profiles {
                    ui.selectable_value(&mut profile, p.clone(), p);
                }
            });
            if profile != v.profile {
                update.profile = Some(profile);
            }
            ui.end_row();

            let mut policy = v.policy.clone();
            for (label, slot) in [
                ("Policy: info", &mut policy.info),
                ("Policy: low", &mut policy.low),
                ("Policy: medium", &mut policy.medium),
                ("Policy: high", &mut policy.high),
                ("Policy: critical", &mut policy.critical),
            ] {
                ui.label(label);
                ui.horizontal(|ui| {
                    ui.selectable_value(slot, PolicyAction::Observe, "Observe");
                    ui.selectable_value(slot, PolicyAction::Alert, "Alert");
                    ui.selectable_value(slot, PolicyAction::Suspend, "Suspend");
                });
                ui.end_row();
            }
            ui.label("Minidump on suspend");
            ui.vertical(|ui| {
                ui.checkbox(&mut policy.minidump, "Write a minidump of suspended processes");
                ui.label(RichText::new("Off by default. Dumps can be hundreds of MB and contain whatever the process already read, including real secrets.").small().weak());
            });
            ui.end_row();
            if policy != v.policy {
                update.policy = Some(policy);
            }

            ui.label("Re-plant automatically");
            let mut ar = v.auto_replant;
            if ui.checkbox(&mut ar, "after a decoy is deleted or modified").changed() {
                update.auto_replant = Some(ar);
            }
            ui.end_row();

            ui.label("Oplock tripwire");
            let mut op = v.oplock;
            if ui.checkbox(&mut op, "early warning independent of ETW (restart service to apply)").changed() {
                update.oplock = Some(op);
            }
            ui.end_row();

            ui.label("Sweep window");
            let mut w = v.sweep_window_secs;
            if ui.add(egui::Slider::new(&mut w, 1..=60).suffix(" s")).changed() {
                update.sweep_window_secs = Some(w);
            }
            ui.end_row();

            ui.label("File sensor");
            let mut mode = v.mode;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut mode, SensorMode::Auto, "ETW (auto fallback)");
                ui.selectable_value(&mut mode, SensorMode::Audit, "SACL auditing only");
            });
            if mode != v.mode {
                update.mode = Some(mode);
            }
            ui.end_row();

            ui.label("Protected profile");
            ui.label(RichText::new(&v.profile_path).monospace());
            ui.end_row();
            ui.label("Data directory");
            ui.label(RichText::new(&v.data_dir).monospace());
            ui.end_row();
        });
        if update != SettingsUpdate::default() {
            self.worker
                .send("settings", Request::SetSettings { update });
        }
    }
}

impl eframe::App for Dashboard {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(150.0)
            .show(ui, |ui| self.nav(ui));
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Overview => {
                egui::ScrollArea::vertical().show(ui, |ui| self.overview(ui));
            }
            Tab::Incidents => self.incidents(ui),
            Tab::Decoys => self.decoys(ui),
            Tab::Allowlist => self.allowlist(ui),
            Tab::Alerts => {
                egui::ScrollArea::vertical().show(ui, |ui| self.alerts(ui));
            }
            Tab::Settings => {
                egui::ScrollArea::vertical().show(ui, |ui| self.settings(ui));
            }
        });
    }
}

/// Writes the JSON, HTML and STIX exports to
/// `%LOCALAPPDATA%\Epicurus\exports` and opens the folder.
fn export(inc: &Incident) -> crate::error::Result<std::path::PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .ok_or(crate::error::UiError::MissingEnv("LOCALAPPDATA"))?;
    let dir = base.join("Epicurus").join("exports");
    epicurus_core::report::export_all(inc, &dir)?;
    let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
    Ok(dir)
}
