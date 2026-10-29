//! Ausschlussregeln für systembekannte Ordner.

/// Kompilierte Ausschlussliste. Vergleich erfolgt segmentweise und ohne
/// Beachtung der Groß-/Kleinschreibung.
#[derive(Debug, Clone, Default)]
pub struct ExcludeSet {
    patterns: Vec<Vec<String>>,
}

impl ExcludeSet {
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out: Vec<Vec<String>> = Vec::new();
        for p in patterns {
            let expanded = expand_env(p.as_ref());
            // Nicht aufgelöste Variablen ignorieren (z. B. %ProgramFiles(x86)% auf 32-Bit).
            if expanded.contains('%') || expanded.trim().is_empty() {
                continue;
            }
            let segs = split(&expanded);
            if !segs.is_empty() && !out.contains(&segs) {
                out.push(segs);
            }
        }
        Self { patterns: out }
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Pfad (ohne `\\?\`-Präfix) ist exakt durch ein Muster ausgeschlossen.
    pub fn is_excluded(&self, path: &str) -> bool {
        let segs = split(path);
        self.patterns.iter().any(|p| {
            p.len() == segs.len()
                && p.iter()
                    .zip(&segs)
                    .all(|(pat, seg)| segment_match(pat, seg))
        })
    }
}

fn split(path: &str) -> Vec<String> {
    path.trim_end_matches(['\\', '/'])
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Glob-Vergleich eines Segments mit `*` und `?`.
fn segment_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Ersetzt `%VAR%` durch Umgebungsvariablen; unbekannte bleiben stehen.
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches() {
        let set = ExcludeSet::new(["?:\\Windows", "?:\\Users\\*\\AppData", "C:\\$Recycle.Bin"]);
        assert!(set.is_excluded("C:\\Windows"));
        assert!(set.is_excluded("d:\\windows\\"));
        assert!(!set.is_excluded("C:\\Windows\\System32"));
        assert!(!set.is_excluded("C:\\WindowsApps"));
        assert!(set.is_excluded("C:\\Users\\max\\AppData"));
        assert!(!set.is_excluded("C:\\Users\\max\\Documents"));
        assert!(set.is_excluded("C:\\$RECYCLE.BIN"));
    }

    #[test]
    fn env() {
        std::env::set_var("PC_TEST_VAR", "C:\\Foo");
        assert_eq!(expand_env("%PC_TEST_VAR%\\bar"), "C:\\Foo\\bar");
        assert_eq!(expand_env("%PC_UNKNOWN_X%"), "%PC_UNKNOWN_X%");
        let set = ExcludeSet::new(["%PC_UNKNOWN_X%", "%PC_TEST_VAR%"]);
        assert_eq!(set.len(), 1);
    }
}
