//! Context-aware Markdown rendering for untrusted review content.

/// Put untrusted text in a CommonMark code span without letting it close the span.
pub(crate) fn code_span(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    let longest = clean.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    if clean.contains('`') {
        format!("{fence} {clean} {fence}")
    } else {
        format!("{fence}{clean}{fence}")
    }
}

/// Escape untrusted inline prose so it cannot create HTML, links, or mentions.
pub(crate) fn prose(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            if character == '\n' || character == '\r' {
                out.push(' ');
            }
            continue;
        }
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '@' => out.push_str("&#64;"),
            '`' => out.push_str("&#96;"),
            '\\' | '*' | '_' | '[' | ']' | '(' | ')' | '!' | '#' | '+' | '-' | '~' => {
                out.push('\\');
                out.push(character);
            }
            _ => out.push(character),
        }
    }
    out
}

/// Escape prose for a Markdown table cell.
pub(crate) fn table_cell(text: &str) -> String {
    prose(text).replace('|', "\\|")
}

/// Render a citation as a pinned GitHub link, or as code spans for symbols.
pub(crate) fn citation(citation: &str, repo: &str, sha: &str) -> String {
    if let Some((path, line)) = citation.rsplit_once(':')
        && !path.is_empty()
        && line.parse::<u32>().is_ok_and(|line| line > 0)
        && safe_path(path)
    {
        let encoded = path
            .split('/')
            .map(encode_path_segment)
            .collect::<Vec<_>>()
            .join("/");
        return format!(
            "[{}](https://github.com/{}/blob/{}/{encoded}#L{})",
            code_span(&format!("{path}:{line}")),
            repo,
            sha,
            line
        );
    }
    if let Some((path, symbol)) = citation.split_once('#') {
        return format!("{} {}", code_span(path), code_span(symbol));
    }
    code_span(citation)
}

fn safe_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn encode_path_segment(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_spans_preserve_path_punctuation_and_choose_a_safe_fence() {
        assert_eq!(code_span("crates/tinyjuice-module/src/savings_store.rs"), "`crates/tinyjuice-module/src/savings_store.rs`");
        assert_eq!(code_span("path`with``ticks.rs"), "``` path`with``ticks.rs ```");
    }

    #[test]
    fn prose_cannot_create_mentions_html_links_or_new_blocks() {
        let rendered = prose("@user <script>[click](https://evil.example)\n# heading");
        assert!(!rendered.contains("@user"));
        assert!(!rendered.contains("<script>"));
        assert!(!rendered.contains("[click]("));
        assert!(!rendered.contains('\n'));
    }

    #[test]
    fn citations_link_lines_at_the_reviewed_commit_and_code_span_symbols() {
        assert_eq!(
            citation("src/savings/ledger.rs:42", "acme/widget", "abc123"),
            "[`src/savings/ledger.rs:42`](https://github.com/acme/widget/blob/abc123/src/savings/ledger.rs#L42)"
        );
        assert_eq!(
            citation("src/savings/ledger.rs#impl SavingsLedger", "acme/widget", "abc123"),
            "`src/savings/ledger.rs` `impl SavingsLedger`"
        );
    }
}
