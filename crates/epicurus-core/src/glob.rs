//! Case-insensitive Windows path globbing for allowlist patterns.
//!
//! `?` matches one character other than `\`, `*` matches any run of
//! characters other than `\`, and `**` matches any run including `\`.

/// True if `path` matches `pattern` (both compared case-insensitively, `/`
/// treated as `\`).
pub fn matches(pattern: &str, path: &str) -> bool {
    let p: Vec<char> = canon(pattern).chars().collect();
    let s: Vec<char> = canon(path).chars().collect();
    match_from(&p, &s)
}

fn canon(s: &str) -> String {
    crate::paths::normalize_key(s)
}

fn match_from(p: &[char], s: &[char]) -> bool {
    // Iterative backtracking over the last star; '**' and '*' tracked
    // separately because only '**' may cross separators.
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize, bool)> = None;
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    let double = pi + 1 < p.len() && p[pi + 1] == '*';
                    let next = if double { pi + 2 } else { pi + 1 };
                    star = Some((next, si, double));
                    pi = next;
                    continue;
                }
                '?' if s[si] != '\\' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                c if c != '?' && c == s[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, ss, double)) if double || s[ss] != '\\' => {
                star = Some((sp, ss + 1, double));
                pi = sp;
                si = ss + 1;
            }
            _ => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn single_star_stays_in_segment() {
        assert!(matches(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe",
            r"c:\programdata\microsoft\windows defender\platform\4.18.25010.11-0\MsMpEng.exe"
        ));
        assert!(!matches(r"C:\a\*\x.exe", r"C:\a\b\c\x.exe"));
        assert!(matches(r"C:\a\*.exe", r"C:\a\tool.exe"));
        assert!(!matches(r"C:\a\*.exe", r"C:\a\b\tool.exe"));
    }

    #[test]
    fn double_star_crosses_segments() {
        assert!(matches(
            r"C:\Program Files\Veeam\**",
            r"C:\Program Files\Veeam\Endpoint Backup\Veeam.EndPoint.Service.exe"
        ));
        assert!(matches(r"C:\a\**\x.exe", r"C:\a\b\c\x.exe"));
        assert!(!matches(r"C:\a\**", r"C:\b\x.exe"));
    }

    #[test]
    fn question_mark_and_literals() {
        assert!(matches(r"C:\a?c", r"C:\abc"));
        assert!(!matches(r"C:\a?c", r"C:\a\c"));
        assert!(!matches(r"C:\abc", r"C:\abcd"));
        assert!(matches("C:/A/B", r"c:\a\b"));
    }
}
