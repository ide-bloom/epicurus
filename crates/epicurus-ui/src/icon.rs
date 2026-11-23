//! Procedurally drawn icons: a rounded shield whose fill reflects status.
//! Drawing them avoids shipping binary assets and keeps the tray color
//! trivially changeable.

/// Status colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Protected.
    Green,
    /// Degraded.
    Amber,
    /// Decision pending / incident.
    Red,
    /// Service unreachable.
    Gray,
}

impl Tone {
    /// RGB fill.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Tone::Green => [0x30, 0xA4, 0x6C],
            Tone::Amber => [0xF5, 0xA5, 0x24],
            Tone::Red => [0xE5, 0x48, 0x4D],
            Tone::Gray => [0x8B, 0x95, 0xA5],
        }
    }
}

/// Signed distance-ish test for a shield outline in unit coordinates.
fn inside_shield(x: f32, y: f32) -> bool {
    // Top part: rounded rectangle; bottom: tapering to a point.
    if !(0.12..=0.88).contains(&x) || !(0.08..=0.94).contains(&y) {
        return false;
    }
    if y < 0.55 {
        // Rounded top corners.
        let (cx, cy, r) = (if x < 0.5 { 0.24 } else { 0.76 }, 0.2, 0.12);
        if y < cy && ((x < 0.24) || (x > 0.76)) {
            return (x - cx).powi(2) + (y - cy).powi(2) <= r * r;
        }
        return true;
    }
    // Below 0.55 the sides converge to (0.5, 0.94).
    let t = (y - 0.55) / (0.94 - 0.55);
    let half = 0.38 * (1.0 - t).max(0.0).sqrt();
    (x - 0.5).abs() <= half
}

/// RGBA pixels of a `size`×`size` shield with an inner check-like glyph.
pub fn shield_rgba(size: u32, tone: Tone) -> Vec<u8> {
    let [r, g, b] = tone.rgb();
    let mut px = vec![0u8; (size * size * 4) as usize];
    let s = size as f32;
    for yy in 0..size {
        for xx in 0..size {
            // 4x supersampling for smooth edges.
            let mut cover = 0u32;
            let mut glyph = 0u32;
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = (xx as f32 + (sx as f32 + 0.5) / 4.0) / s;
                    let y = (yy as f32 + (sy as f32 + 0.5) / 4.0) / s;
                    if inside_shield(x, y) {
                        cover += 1;
                        // A small inner "E" bar glyph in white.
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
            let i = ((yy * size + xx) * 4) as usize;
            if cover > 0 {
                let gfrac = glyph as f32 / cover as f32;
                let mix = |c: u8| (c as f32 * (1.0 - gfrac) + 255.0 * gfrac) as u8;
                px[i] = mix(r);
                px[i + 1] = mix(g);
                px[i + 2] = mix(b);
                px[i + 3] = (cover * 255 / 16) as u8;
            }
        }
    }
    px
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_expected_size_and_transparency() {
        let px = shield_rgba(32, Tone::Green);
        assert_eq!(px.len(), 32 * 32 * 4);
        assert_eq!(px[3], 0, "corner is transparent");
        let center = ((16 * 32 + 16) * 4) as usize;
        assert_eq!(px[center + 3], 255, "center is opaque");
    }
}
