//! Embeds Windows resources into epicurus.exe: the application icon, an
//! application manifest, version information and the Event Log message
//! table (so Event Viewer renders Epicurus events without "description not
//! found" noise). Everything is generated here; no binary assets are
//! committed.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Event id ranges covered by the message table. Every id in
/// `epicurus_service::eventlog::ALL_IDS` falls in one of these.
const ID_RANGES: &[(u32, u32)] = &[(1000, 1099), (2000, 2099), (3000, 3099), (9000, 9009)];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let ico = out.join("epicurus.ico");
    let manifest = out.join("epicurus.manifest");
    let msg = out.join("messages.bin");
    let rc = out.join("epicurus.rc");

    write(&ico, &icon_file());
    write(&manifest, MANIFEST.as_bytes());
    write(&msg, &message_table());
    write(&rc, rc_script(&ico, &manifest, &msg).as_bytes());

    // A missing resource compiler must not break `cargo check` on machines
    // without the Windows SDK; release builds on CI always have it.
    if let Err(e) = embed_resource::compile(&rc, embed_resource::NONE).manifest_optional() {
        println!("cargo:warning=resources not embedded: {e}");
    }
}

fn write(path: &Path, bytes: &[u8]) {
    if let Err(e) = std::fs::write(path, bytes) {
        println!("cargo:warning=could not write {}: {e}", path.display());
    }
}

fn rc_escape(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\")
}

fn rc_script(ico: &Path, manifest: &Path, msg: &Path) -> String {
    let v = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let parts: Vec<u32> = v
        .split(['.', '-'])
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    let (ma, mi, pa) = (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    );
    let mut s = String::new();
    let _ = writeln!(s, "#pragma code_page(65001)");
    let _ = writeln!(s, "1 ICON \"{}\"", rc_escape(ico));
    let _ = writeln!(s, "1 24 \"{}\"", rc_escape(manifest));
    let _ = writeln!(s, "1 MESSAGETABLE \"{}\"", rc_escape(msg));
    let _ = writeln!(
        s,
        r#"1 VERSIONINFO
FILEVERSION {ma},{mi},{pa},0
PRODUCTVERSION {ma},{mi},{pa},0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Epicurus contributors"
      VALUE "FileDescription", "Epicurus infostealer tripwire"
      VALUE "FileVersion", "{v}"
      VALUE "InternalName", "epicurus"
      VALUE "LegalCopyright", "MIT OR Apache-2.0"
      VALUE "OriginalFilename", "epicurus.exe"
      VALUE "ProductName", "Epicurus"
      VALUE "ProductVersion", "{v}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END"#
    );
    s
}

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="IdeBloom.Epicurus" version="1.0.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <!-- Elevation is requested at runtime only for commands that need it. -->
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#;

/// MESSAGE_RESOURCE_DATA with one block per range; every message is "%1",
/// so Event Viewer shows the insertion string Epicurus writes.
fn message_table() -> Vec<u8> {
    let entry: Vec<u8> = {
        let text: Vec<u16> = "%1\r\n\0".encode_utf16().collect();
        let mut body: Vec<u8> = text.iter().flat_map(|c| c.to_le_bytes()).collect();
        while !(body.len() + 4).is_multiple_of(4) {
            body.push(0);
        }
        let mut e = Vec::new();
        e.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
        e.extend_from_slice(&1u16.to_le_bytes()); // MESSAGE_RESOURCE_UNICODE
        e.extend_from_slice(&body);
        e
    };
    let header_len = 4 + ID_RANGES.len() * 12;
    let mut blocks = Vec::new();
    let mut entries = Vec::new();
    for &(lo, hi) in ID_RANGES {
        let offset = header_len + entries.len();
        blocks.extend_from_slice(&lo.to_le_bytes());
        blocks.extend_from_slice(&hi.to_le_bytes());
        blocks.extend_from_slice(&(offset as u32).to_le_bytes());
        for _ in lo..=hi {
            entries.extend_from_slice(&entry);
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(ID_RANGES.len() as u32).to_le_bytes());
    out.extend(blocks);
    out.extend(entries);
    out
}

// --- icon -------------------------------------------------------------------
// Same shield as crates/epicurus-ui/src/icon.rs, drawn here because build
// scripts cannot depend on the crates they build.

fn inside_shield(x: f32, y: f32) -> bool {
    if !(0.12..=0.88).contains(&x) || !(0.08..=0.94).contains(&y) {
        return false;
    }
    if y < 0.55 {
        let (cx, cy, r) = (if x < 0.5 { 0.24 } else { 0.76 }, 0.2, 0.12);
        if y < cy && ((x < 0.24) || (x > 0.76)) {
            return (x - cx).powi(2) + (y - cy).powi(2) <= r * r;
        }
        return true;
    }
    let t = (y - 0.55) / (0.94 - 0.55);
    let half = 0.38 * (1.0 - t).max(0.0).sqrt();
    (x - 0.5).abs() <= half
}

fn shield_bgra(size: u32) -> Vec<u8> {
    let (r, g, b) = (0x30u8, 0xA4u8, 0x6Cu8);
    let s = size as f32;
    let mut px = vec![0u8; (size * size * 4) as usize];
    for yy in 0..size {
        for xx in 0..size {
            let mut cover = 0u32;
            let mut glyph = 0u32;
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = (xx as f32 + (sx as f32 + 0.5) / 4.0) / s;
                    let y = (yy as f32 + (sy as f32 + 0.5) / 4.0) / s;
                    if inside_shield(x, y) {
                        cover += 1;
                        let in_glyph = (0.36..=0.64).contains(&x)
                            && ((0.28..=0.36).contains(&y)
                                || (0.44..=0.52).contains(&y)
                                || (0.60..=0.68).contains(&y))
                            || ((0.36..=0.44).contains(&x) && (0.28..=0.68).contains(&y));
                        if in_glyph {
                            glyph += 1;
                        }
                    }
                }
            }
            // ICO bitmaps are stored bottom-up.
            let row = size - 1 - yy;
            let i = ((row * size + xx) * 4) as usize;
            if cover > 0 {
                let f = glyph as f32 / cover as f32;
                let mix = |c: u8| (c as f32 * (1.0 - f) + 255.0 * f) as u8;
                px[i] = mix(b);
                px[i + 1] = mix(g);
                px[i + 2] = mix(r);
                px[i + 3] = (cover * 255 / 16) as u8;
            }
        }
    }
    px
}

fn icon_file() -> Vec<u8> {
    let sizes = [16u32, 24, 32, 48, 64, 128, 256];
    let images: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&sz| {
            let mut img = Vec::new();
            // BITMAPINFOHEADER; height is doubled to include the AND mask.
            img.extend_from_slice(&40u32.to_le_bytes());
            img.extend_from_slice(&(sz as i32).to_le_bytes());
            img.extend_from_slice(&((sz * 2) as i32).to_le_bytes());
            img.extend_from_slice(&1u16.to_le_bytes());
            img.extend_from_slice(&32u16.to_le_bytes());
            img.extend_from_slice(&[0u8; 24]);
            img.extend(shield_bgra(sz));
            let mask_row = (sz.div_ceil(32) * 4) as usize;
            img.extend(std::iter::repeat_n(0u8, mask_row * sz as usize));
            img
        })
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len();
    for (sz, img) in sizes.iter().zip(&images) {
        let dim = if *sz >= 256 { 0u8 } else { *sz as u8 };
        out.push(dim);
        out.push(dim);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += img.len();
    }
    for img in images {
        out.extend(img);
    }
    out
}
