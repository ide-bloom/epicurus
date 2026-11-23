//! `epicurus.exe`: the single binary that installs, runs and drives
//! Epicurus.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(not(windows))]
compile_error!("Epicurus targets Windows only (x86_64-pc-windows-msvc, aarch64-pc-windows-msvc).");

mod commands;
mod elevate;
mod install;
mod logging;
mod shortcut;
mod simulate;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// An open-source Windows tripwire that catches infostealers.
#[derive(Debug, Parser)]
#[command(name = "epicurus", version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    /// Named pipe of the service (advanced; used by tests).
    #[arg(long, global = true, hide = true, default_value = epicurus_core::DEFAULT_PIPE_NAME)]
    pipe: String,
    /// Data directory override (advanced; used by tests).
    #[arg(long, global = true, hide = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install the service, plant the default decoys and start protecting.
    Install {
        /// Catalog profile to plant (default, ai, developer, minimal).
        #[arg(long)]
        profile: Option<String>,
        /// Install without planting decoys.
        #[arg(long)]
        no_plant: bool,
        /// SID of the user to protect (passed by the elevation relaunch).
        #[arg(long, hide = true)]
        user_sid: Option<String>,
        /// File the elevated child writes its output to.
        #[arg(long, hide = true)]
        report: Option<PathBuf>,
    },
    /// Remove decoys, the service, the shortcut and (unless --keep-data) all data.
    Uninstall {
        /// Keep %ProgramData%\Epicurus (incidents, config, logs).
        #[arg(long)]
        keep_data: bool,
        /// File the elevated child writes its output to.
        #[arg(long, hide = true)]
        report: Option<PathBuf>,
    },
    /// Plant decoys.
    Plant {
        /// Catalog profile.
        #[arg(long)]
        profile: Option<String>,
        /// Print the full plan and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove all decoys whose content is unchanged.
    Unplant,
    /// Protection state, sensor health, decoy counts and recent incidents.
    Status {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Open the dashboard.
    Ui {
        /// Run the notification-area agent instead of the window.
        #[arg(long)]
        tray: bool,
        /// Open this incident.
        #[arg(long)]
        incident: Option<String>,
    },
    /// List incidents.
    Incidents {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Maximum rows.
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Write the JSON, HTML and STIX 2.1 reports for one incident.
    Export {
        /// Incident id (inc_...).
        id: String,
        /// Output directory (default: current directory).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run the built-in harmless stealer simulation.
    Simulate {
        /// Seconds the simulated stealer lingers after its sweep.
        #[arg(long, default_value_t = 60)]
        linger_secs: u64,
        /// Leave the simulated process suspended instead of killing it afterwards.
        #[arg(long)]
        keep: bool,
    },
    /// Diagnose privileges, sensors, oplock support, conflicts and synced folders.
    Doctor {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Service entry point (started by the Service Control Manager).
    #[command(hide = true)]
    Service {
        /// Run in the foreground instead of under the SCM.
        #[arg(long)]
        foreground: bool,
        /// ETW session name override.
        #[arg(long)]
        session_name: Option<String>,
        /// Protected profile root override.
        #[arg(long)]
        profile_root: Option<PathBuf>,
        /// Protected user SID override.
        #[arg(long)]
        user_sid: Option<String>,
    },
    /// The simulated stealer child process (internal).
    #[command(name = "__simulate-stealer", hide = true)]
    SimulateStealer {
        /// Seconds to linger after the sweep.
        #[arg(long, default_value_t = 60)]
        linger_secs: u64,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = run(cli);
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let data = cli
        .data_dir
        .clone()
        .map(epicurus_core::paths::DataDir::new)
        .unwrap_or_else(epicurus_core::paths::DataDir::system);
    match cli.cmd {
        Command::Service {
            foreground,
            session_name,
            profile_root,
            user_sid,
        } => {
            let _guard = logging::init_service(&data, foreground);
            if foreground {
                commands::service_foreground(
                    &cli.pipe,
                    data,
                    session_name,
                    profile_root,
                    user_sid,
                )?;
            } else {
                epicurus_service::host::run_as_service()?;
            }
            Ok(0)
        }
        Command::SimulateStealer { linger_secs } => {
            simulate::child(&cli.pipe, linger_secs)?;
            Ok(0)
        }
        Command::Ui { tray, incident } => {
            let _guard = logging::init_user();
            let verifier = commands::verifier(&cli.pipe);
            if tray {
                epicurus_ui::tray::run(cli.pipe, verifier)?;
            } else {
                epicurus_ui::run_dashboard(cli.pipe, verifier, incident)?;
            }
            Ok(0)
        }
        Command::Install {
            profile,
            no_plant,
            user_sid,
            report,
        } => {
            let _guard = logging::init_cli(&data);
            install::install(&cli.pipe, &data, profile, no_plant, user_sid, report)
        }
        Command::Uninstall { keep_data, report } => {
            let _guard = logging::init_cli(&data);
            install::uninstall(&cli.pipe, &data, keep_data, report)
        }
        other => {
            let _guard = logging::init_cli(&data);
            match other {
                Command::Plant { profile, dry_run } => {
                    commands::plant(&cli.pipe, &data, profile, dry_run)
                }
                Command::Unplant => commands::unplant(&cli.pipe, &data),
                Command::Status { json } => commands::status(&cli.pipe, &data, json),
                Command::Incidents { json, limit } => {
                    commands::incidents(&cli.pipe, &data, json, limit)
                }
                Command::Export { id, out } => commands::export(&cli.pipe, &data, &id, out),
                Command::Simulate { linger_secs, keep } => {
                    simulate::parent(&cli.pipe, linger_secs, keep)
                }
                Command::Doctor { json } => commands::doctor(&cli.pipe, &data, json),
                _ => Ok(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_documented_commands() {
        for args in [
            vec!["epicurus", "install"],
            vec!["epicurus", "uninstall", "--keep-data"],
            vec!["epicurus", "plant", "--profile", "ai", "--dry-run"],
            vec!["epicurus", "unplant"],
            vec!["epicurus", "status"],
            vec!["epicurus", "ui"],
            vec!["epicurus", "incidents", "--json"],
            vec!["epicurus", "export", "inc_0123456789abcdef"],
            vec!["epicurus", "simulate"],
            vec!["epicurus", "doctor"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn simulator_flag_matches_core_constant() {
        let c = Cli::try_parse_from(["epicurus", epicurus_core::SIMULATOR_FLAG]).unwrap();
        assert!(matches!(c.cmd, Command::SimulateStealer { .. }));
    }
}
