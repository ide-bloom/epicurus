//! UAC elevation: relaunch the current executable with the "runas" verb and
//! relay the elevated child's output, which it writes to a report file
//! because its console window is hidden.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{PCWSTR, w};

use epicurus_sensor::winutil::wide;

/// Quotes one argument for the Windows command line.
pub fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// A fresh report file path in the temp directory.
pub fn report_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "epicurus-elevated-{}-{}.log",
        std::process::id(),
        epicurus_core::generators::random_uuid()
    ))
}

/// Relaunches elevated with `args`, waits, prints the child's report and
/// returns its exit code.
pub fn relaunch(args: &[String], report: &Path) -> anyhow::Result<u8> {
    let exe = std::env::current_exe()?;
    let params: Vec<String> = args.iter().map(|a| quote(a)).collect();
    let wexe = wide(&exe);
    let wparams = wide(params.join(" "));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(wexe.as_ptr()),
        lpParameters: PCWSTR(wparams.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    println!("Requesting administrator rights...");
    // SAFETY: info is fully initialized and its strings outlive the call.
    unsafe { ShellExecuteExW(&mut info) }
        .map_err(|e| anyhow::anyhow!("elevation was cancelled or failed: {}", e.message()))?;
    let mut code = 1u32;
    if !info.hProcess.is_invalid() {
        // SAFETY: we own the process handle returned by ShellExecuteExW.
        unsafe {
            if WaitForSingleObject(info.hProcess, INFINITE) == WAIT_OBJECT_0 {
                let _ = GetExitCodeProcess(info.hProcess, &mut code);
            }
            let _ = CloseHandle(info.hProcess);
        }
    }
    if let Ok(text) = std::fs::read_to_string(report) {
        print!("{text}");
        let _ = std::fs::remove_file(report);
    }
    Ok(u8::try_from(code).unwrap_or(1))
}

/// Output sink for commands that may run elevated: writes to stdout and,
/// when a report path is given, to that file as well.
pub struct Out {
    file: Option<std::fs::File>,
}

impl Out {
    /// Opens the sink.
    pub fn new(report: Option<&Path>) -> Self {
        Self {
            file: report.and_then(|p| std::fs::File::create(p).ok()),
        }
    }

    /// Prints a line.
    pub fn line(&mut self, s: impl AsRef<str>) {
        use std::io::Write;
        println!("{}", s.as_ref());
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{}", s.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn quoting_follows_windows_rules() {
        assert_eq!(quote("simple"), "simple");
        assert_eq!(quote("with space"), "\"with space\"");
        assert_eq!(quote(r"C:\Program Files\x\"), r#""C:\Program Files\x\\""#);
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote(""), "\"\"");
    }
}
