//! Term formatting infrastructure for displaying Erlang terms in various BEAM language syntaxes.
//!
//! This module provides the `TermFormatter` trait and factory function for creating formatters
//! that render Erlang terms in the syntax of different BEAM languages (Erlang, Elixir, Gleam, LFE).

use crate::server::FormatterMode;
use eetf::{Pid, Reference, Term};

/// Trait for formatting Erlang terms into string representations.
///
/// Implementors of this trait provide language-specific formatting for all Erlang term types.
/// The methods are designed to handle both simple and complex nested terms recursively.
pub trait TermFormatter: Send + Sync {
    /// Format any Erlang term. This is the main entry point for formatting.
    fn format_term(&self, term: &Term) -> String;

    /// Format an atom.
    ///
    /// Atoms may require quoting depending on their content and the target language.
    fn format_atom(&self, name: &str) -> String;

    /// Format a tuple.
    ///
    /// The elements should be recursively formatted using `format_term`.
    fn format_tuple(&self, elements: &[Term]) -> String;

    /// Format a list.
    ///
    /// The elements should be recursively formatted using `format_term`.
    /// Some formatters may detect special cases like charlists or keyword lists.
    fn format_list(&self, elements: &[Term]) -> String;

    /// Format a map.
    ///
    /// The key-value pairs should be recursively formatted using `format_term`.
    fn format_map(&self, entries: &[(Term, Term)]) -> String;

    /// Format a process identifier (PID).
    fn format_pid(&self, pid: &Pid) -> String;

    /// Format a reference.
    fn format_reference(&self, reference: &Reference) -> String;

    /// Format a binary.
    ///
    /// The formatter should detect whether the binary is valid UTF-8 text
    /// or raw bytes and format accordingly.
    fn format_binary(&self, bytes: &[u8]) -> String;
}

/// Returns a boxed formatter for the given mode.
///
/// This is the factory function for creating formatters. Each mode
/// produces a formatter that outputs terms in that language's syntax.
pub fn get_formatter(mode: FormatterMode) -> Box<dyn TermFormatter> {
    match mode {
        FormatterMode::Erlang => Box::new(ErlangFormatter),
        FormatterMode::Elixir => Box::new(ElixirFormatter),
        FormatterMode::Gleam => Box::new(GleamFormatter),
        FormatterMode::Lfe => Box::new(LfeFormatter),
    }
}

/// Placeholder Erlang formatter.
///
/// Full implementation will be provided in US-007.
struct ErlangFormatter;

impl ErlangFormatter {
    fn format_term_indent(&self, term: &Term, indent: usize) -> String {
        match term {
            Term::Atom(a) => self.format_atom(&a.name),
            Term::FixInteger(i) => i.value.to_string(),
            Term::BigInteger(i) => i.value.to_string(),
            Term::Float(f) => format!("{}", f.value),
            Term::Binary(b) => self.format_binary(&b.bytes),
            Term::Tuple(t) => self.format_tuple_indent(&t.elements, indent),
            Term::List(l) => {
                if l.is_nil() {
                    "[]".to_string()
                } else {
                    self.format_list_indent(&l.elements, indent)
                }
            }
            Term::Map(m) => {
                let entries: Vec<(Term, Term)> =
                    m.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                self.format_map_indent(&entries, indent)
            }
            Term::Pid(p) => self.format_pid(p),
            Term::Reference(r) => self.format_reference(r),
            Term::BitBinary(bb) => {
                let total_bits = bb.bytes.len() * 8 + bb.tail_bits_size as usize;
                format!("<<{} bits>>", total_bits)
            }
            Term::ByteList(bl) => self.format_binary(&bl.bytes),
            _ => format!("{:?}", term),
        }
    }

    fn format_tuple_indent(&self, elements: &[Term], indent: usize) -> String {
        if should_format_multiline(elements) {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = elements
                .iter()
                .map(|e| format!("{}{}", indent_str, self.format_term_indent(e, new_indent)))
                .collect();
            format!("{{\n{}\n{}}}", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = elements
                .iter()
                .map(|e| self.format_term_indent(e, indent))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }

    fn format_list_indent(&self, elements: &[Term], indent: usize) -> String {
        // Check if this is a charlist (string)
        if let Some(s) = try_as_charlist(elements) {
            return format!("\"{}\"", escape_string(&s));
        }

        if should_format_multiline(elements) {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = elements
                .iter()
                .map(|e| format!("{}{}", indent_str, self.format_term_indent(e, new_indent)))
                .collect();
            format!("[\n{}\n{}]", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = elements
                .iter()
                .map(|e| self.format_term_indent(e, indent))
                .collect();
            format!("[{}]", inner.join(", "))
        }
    }

    fn format_map_indent(&self, entries: &[(Term, Term)], indent: usize) -> String {
        if entries.len() > 3 {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}{} => {}",
                        indent_str,
                        self.format_term_indent(k, new_indent),
                        self.format_term_indent(v, new_indent)
                    )
                })
                .collect();
            format!("#{{\n{}\n{}}}", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{} => {}",
                        self.format_term_indent(k, indent),
                        self.format_term_indent(v, indent)
                    )
                })
                .collect();
            format!("#{{{}}}", inner.join(", "))
        }
    }
}

impl TermFormatter for ErlangFormatter {
    fn format_term(&self, term: &Term) -> String {
        self.format_term_indent(term, 0)
    }

    fn format_atom(&self, name: &str) -> String {
        if needs_quoting(name) {
            format!("'{}'", name)
        } else {
            name.to_string()
        }
    }

    fn format_tuple(&self, elements: &[Term]) -> String {
        self.format_tuple_indent(elements, 0)
    }

    fn format_list(&self, elements: &[Term]) -> String {
        self.format_list_indent(elements, 0)
    }

    fn format_map(&self, entries: &[(Term, Term)]) -> String {
        self.format_map_indent(entries, 0)
    }

    fn format_pid(&self, pid: &Pid) -> String {
        format!("<{}.{}.{}>", pid.node.name, pid.id, pid.serial)
    }

    fn format_reference(&self, reference: &Reference) -> String {
        let id_str: Vec<String> = reference.id.iter().map(|i| i.to_string()).collect();
        format!("#Ref<{}.{}>", reference.node.name, id_str.join("."))
    }

    fn format_binary(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "<<>>".to_string();
        }
        if let Ok(s) = std::str::from_utf8(bytes)
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return format!("<<\"{}\">>", s);
        }
        let byte_str: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("<<{}>>", byte_str.join(","))
    }
}

/// Elixir formatter - formats terms in idiomatic Elixir syntax.
///
/// Full implementation for US-008.
struct ElixirFormatter;

impl ElixirFormatter {
    fn format_term_indent(&self, term: &Term, indent: usize) -> String {
        match term {
            Term::Atom(a) => self.format_atom(&a.name),
            Term::FixInteger(i) => i.value.to_string(),
            Term::BigInteger(i) => i.value.to_string(),
            Term::Float(f) => format!("{}", f.value),
            Term::Binary(b) => self.format_binary(&b.bytes),
            Term::Tuple(t) => self.format_tuple_indent(&t.elements, indent),
            Term::List(l) => {
                if l.is_nil() {
                    "[]".to_string()
                } else {
                    self.format_list_indent(&l.elements, indent)
                }
            }
            Term::Map(m) => {
                let entries: Vec<(Term, Term)> =
                    m.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                self.format_map_indent(&entries, indent)
            }
            Term::Pid(p) => self.format_pid(p),
            Term::Reference(r) => self.format_reference(r),
            Term::BitBinary(bb) => {
                let total_bits = bb.bytes.len() * 8 + bb.tail_bits_size as usize;
                format!("<<_::{} bits>>", total_bits)
            }
            Term::ByteList(bl) => self.format_binary(&bl.bytes),
            _ => format!("{:?}", term),
        }
    }

    fn format_tuple_indent(&self, elements: &[Term], indent: usize) -> String {
        if should_format_multiline(elements) {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = elements
                .iter()
                .map(|e| format!("{}{}", indent_str, self.format_term_indent(e, new_indent)))
                .collect();
            format!("{{\n{}\n{}}}", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = elements
                .iter()
                .map(|e| self.format_term_indent(e, indent))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }

    fn format_list_indent(&self, elements: &[Term], indent: usize) -> String {
        // Check if this is a charlist (string)
        if let Some(s) = try_as_charlist(elements) {
            return format!("~c\"{}\"", escape_string(&s));
        }

        // Check if this is a keyword list
        if is_keyword_list(elements) {
            return self.format_keyword_list(elements, indent);
        }

        if should_format_multiline(elements) {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = elements
                .iter()
                .map(|e| format!("{}{}", indent_str, self.format_term_indent(e, new_indent)))
                .collect();
            format!("[\n{}\n{}]", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = elements
                .iter()
                .map(|e| self.format_term_indent(e, indent))
                .collect();
            format!("[{}]", inner.join(", "))
        }
    }

    fn format_keyword_list(&self, elements: &[Term], indent: usize) -> String {
        let items: Vec<String> = elements
            .iter()
            .filter_map(|term| {
                if let Term::Tuple(t) = term
                    && t.elements.len() == 2
                    && let Term::Atom(key) = &t.elements[0]
                {
                    Some(format!(
                        "{}: {}",
                        self.format_atom_for_keyword(&key.name),
                        self.format_term_indent(&t.elements[1], indent)
                    ))
                } else {
                    None
                }
            })
            .collect();
        format!("[{}]", items.join(", "))
    }

    fn format_atom_for_keyword(&self, name: &str) -> String {
        // For keyword list keys, just use the atom name without the leading :
        if needs_quoting(name) {
            format!("\"{}\"", name)
        } else {
            name.to_string()
        }
    }

    fn format_map_indent(&self, entries: &[(Term, Term)], indent: usize) -> String {
        // Check if this is a struct (has __struct__ key)
        if let Some(struct_name) = extract_struct_name(entries) {
            return self.format_struct(&struct_name, entries, indent);
        }

        // Check if all keys are atoms - use shorthand syntax
        let all_atom_keys = entries.iter().all(|(k, _)| matches!(k, Term::Atom(_)));

        if entries.len() > 3 {
            let new_indent = indent + 2;
            let indent_str = " ".repeat(new_indent);
            let inner: Vec<String> = entries
                .iter()
                .filter(|(k, _)| !is_struct_key(k)) // Skip __struct__ key in display
                .map(|(k, v)| {
                    if all_atom_keys && let Term::Atom(a) = k {
                        format!(
                            "{}{}: {}",
                            indent_str,
                            self.format_atom_for_keyword(&a.name),
                            self.format_term_indent(v, new_indent)
                        )
                    } else {
                        format!(
                            "{}{} => {}",
                            indent_str,
                            self.format_term_indent(k, new_indent),
                            self.format_term_indent(v, new_indent)
                        )
                    }
                })
                .collect();
            format!("%{{\n{}\n{}}}", inner.join(",\n"), " ".repeat(indent))
        } else {
            let inner: Vec<String> = entries
                .iter()
                .filter(|(k, _)| !is_struct_key(k))
                .map(|(k, v)| {
                    if all_atom_keys && let Term::Atom(a) = k {
                        format!(
                            "{}: {}",
                            self.format_atom_for_keyword(&a.name),
                            self.format_term_indent(v, indent)
                        )
                    } else {
                        format!(
                            "{} => {}",
                            self.format_term_indent(k, indent),
                            self.format_term_indent(v, indent)
                        )
                    }
                })
                .collect();
            format!("%{{{}}}", inner.join(", "))
        }
    }

    fn format_struct(&self, struct_name: &str, entries: &[(Term, Term)], indent: usize) -> String {
        let module_name = format_module_name(struct_name);

        let fields: Vec<String> = entries
            .iter()
            .filter(|(k, _)| !is_struct_key(k))
            .map(|(k, v)| {
                if let Term::Atom(a) = k {
                    format!(
                        "{}: {}",
                        self.format_atom_for_keyword(&a.name),
                        self.format_term_indent(v, indent)
                    )
                } else {
                    format!(
                        "{} => {}",
                        self.format_term_indent(k, indent),
                        self.format_term_indent(v, indent)
                    )
                }
            })
            .collect();

        if fields.is_empty() {
            format!("%{}{{}}", module_name)
        } else {
            format!("%{}{{{}}}", module_name, fields.join(", "))
        }
    }
}

impl TermFormatter for ElixirFormatter {
    fn format_term(&self, term: &Term) -> String {
        self.format_term_indent(term, 0)
    }

    fn format_atom(&self, name: &str) -> String {
        // Check if this is a module atom (starts with Elixir.)
        let formatted_name = format_module_name(name);
        if formatted_name != name {
            // It's a module, return without :
            formatted_name
        } else if needs_quoting(name) {
            format!(":\"{}\"", name)
        } else {
            format!(":{}", name)
        }
    }

    fn format_tuple(&self, elements: &[Term]) -> String {
        self.format_tuple_indent(elements, 0)
    }

    fn format_list(&self, elements: &[Term]) -> String {
        self.format_list_indent(elements, 0)
    }

    fn format_map(&self, entries: &[(Term, Term)]) -> String {
        self.format_map_indent(entries, 0)
    }

    fn format_pid(&self, pid: &Pid) -> String {
        format!("#PID<{}.{}.{}>", pid.node.name, pid.id, pid.serial)
    }

    fn format_reference(&self, reference: &Reference) -> String {
        let id_str: Vec<String> = reference.id.iter().map(|i| i.to_string()).collect();
        format!("#Reference<{}.{}>", reference.node.name, id_str.join("."))
    }

    fn format_binary(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "\"\"".to_string();
        }
        if let Ok(s) = std::str::from_utf8(bytes)
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return format!("\"{}\"", escape_string(s));
        }
        let byte_str: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("<<{}>>", byte_str.join(", "))
    }
}

/// Gleam formatter - formats terms in Gleam-like syntax where possible.
///
/// Full implementation for US-009.
struct GleamFormatter;

impl GleamFormatter {
    /// Check if a tuple is a Gleam Result type and format accordingly.
    ///
    /// Returns Some(formatted) if it's an Ok or Error tuple, None otherwise.
    fn try_format_result_tuple(&self, elements: &[Term]) -> Option<String> {
        if elements.len() != 2 {
            return None;
        }

        if let Term::Atom(tag) = &elements[0] {
            match tag.name.as_str() {
                "ok" => Some(format!("Ok({})", self.format_term(&elements[1]))),
                "error" => Some(format!("Error({})", self.format_term(&elements[1]))),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl TermFormatter for GleamFormatter {
    fn format_term(&self, term: &Term) -> String {
        match term {
            Term::Atom(a) => self.format_atom(&a.name),
            Term::FixInteger(i) => i.value.to_string(),
            Term::BigInteger(i) => i.value.to_string(),
            Term::Float(f) => format!("{}", f.value),
            Term::Binary(b) => self.format_binary(&b.bytes),
            Term::Tuple(t) => self.format_tuple(&t.elements),
            Term::List(l) => {
                if l.is_nil() {
                    "[]".to_string()
                } else {
                    self.format_list(&l.elements)
                }
            }
            Term::Map(m) => {
                let entries: Vec<(Term, Term)> =
                    m.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                self.format_map(&entries)
            }
            Term::Pid(p) => self.format_pid(p),
            Term::Reference(r) => self.format_reference(r),
            Term::BitBinary(bb) => {
                let total_bits = bb.bytes.len() * 8 + bb.tail_bits_size as usize;
                format!("<<_::{} bits>>", total_bits)
            }
            Term::ByteList(bl) => self.format_binary(&bl.bytes),
            _ => format!("{:?}", term),
        }
    }

    fn format_atom(&self, name: &str) -> String {
        if needs_quoting(name) {
            format!("'{}' // Note: Erlang-style atom", name)
        } else {
            format!("{} // Note: Erlang-style atom", name)
        }
    }

    fn format_tuple(&self, elements: &[Term]) -> String {
        // Try to format as Result type first
        if let Some(result) = self.try_format_result_tuple(elements) {
            return result;
        }

        // Otherwise format as Gleam tuple
        let inner: Vec<String> = elements.iter().map(|e| self.format_term(e)).collect();
        format!("#({})", inner.join(", "))
    }

    fn format_list(&self, elements: &[Term]) -> String {
        let inner: Vec<String> = elements.iter().map(|e| self.format_term(e)).collect();
        format!("[{}]", inner.join(", "))
    }

    fn format_map(&self, entries: &[(Term, Term)]) -> String {
        let inner: Vec<String> = entries
            .iter()
            .map(|(k, v)| format!("#({}, {})", self.format_term(k), self.format_term(v)))
            .collect();
        format!("dict.from_list([{}])", inner.join(", "))
    }

    fn format_pid(&self, pid: &Pid) -> String {
        format!("//pid<{}.{}.{}>", pid.node.name, pid.id, pid.serial)
    }

    fn format_reference(&self, reference: &Reference) -> String {
        let id_str: Vec<String> = reference.id.iter().map(|i| i.to_string()).collect();
        format!("//ref<{}.{}>", reference.node.name, id_str.join("."))
    }

    fn format_binary(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "\"\"".to_string();
        }
        if let Ok(s) = std::str::from_utf8(bytes)
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return format!("\"{}\"", escape_string(s));
        }
        let byte_str: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("<<{}>>", byte_str.join(", "))
    }
}

/// Placeholder LFE (Lisp Flavoured Erlang) formatter.
///
/// Full implementation will be provided in US-010.
struct LfeFormatter;

impl TermFormatter for LfeFormatter {
    fn format_term(&self, term: &Term) -> String {
        match term {
            Term::Atom(a) => self.format_atom(&a.name),
            Term::FixInteger(i) => i.value.to_string(),
            Term::BigInteger(i) => i.value.to_string(),
            Term::Float(f) => format!("{}", f.value),
            Term::Binary(b) => self.format_binary(&b.bytes),
            Term::Tuple(t) => self.format_tuple(&t.elements),
            Term::List(l) => {
                if l.is_nil() {
                    "()".to_string()
                } else {
                    self.format_list(&l.elements)
                }
            }
            Term::Map(m) => {
                let entries: Vec<(Term, Term)> =
                    m.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                self.format_map(&entries)
            }
            Term::Pid(p) => self.format_pid(p),
            Term::Reference(r) => self.format_reference(r),
            Term::BitBinary(bb) => {
                let total_bits = bb.bytes.len() * 8 + bb.tail_bits_size as usize;
                format!("#B({} bits)", total_bits)
            }
            Term::ByteList(bl) => self.format_binary(&bl.bytes),
            _ => format!("{:?}", term),
        }
    }

    fn format_atom(&self, name: &str) -> String {
        if name.is_empty() {
            "'||".to_string()
        } else if name.contains(' ') || name.contains('|') {
            format!("'|{}|", name)
        } else {
            format!("'{}", name)
        }
    }

    fn format_tuple(&self, elements: &[Term]) -> String {
        let inner: Vec<String> = elements.iter().map(|e| self.format_term(e)).collect();
        format!("#({})", inner.join(" "))
    }

    fn format_list(&self, elements: &[Term]) -> String {
        let inner: Vec<String> = elements.iter().map(|e| self.format_term(e)).collect();
        format!("'({})", inner.join(" "))
    }

    fn format_map(&self, entries: &[(Term, Term)]) -> String {
        let inner: Vec<String> = entries
            .iter()
            .map(|(k, v)| format!("{} {}", self.format_term(k), self.format_term(v)))
            .collect();
        format!("#m({})", inner.join(" "))
    }

    fn format_pid(&self, pid: &Pid) -> String {
        format!("#Pid<{}.{}.{}>", pid.node.name, pid.id, pid.serial)
    }

    fn format_reference(&self, reference: &Reference) -> String {
        let id_str: Vec<String> = reference.id.iter().map(|i| i.to_string()).collect();
        format!("#Ref<{}.{}>", reference.node.name, id_str.join("."))
    }

    fn format_binary(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "\"\"".to_string();
        }
        if let Ok(s) = std::str::from_utf8(bytes)
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return format!("\"{}\"", escape_string(s));
        }
        let byte_str: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("#B({})", byte_str.join(" "))
    }
}

/// Check if an atom name needs quoting in Erlang syntax.
///
/// Atoms need quoting if they:
/// - Start with an uppercase letter
/// - Contain special characters (not alphanumeric or underscore)
/// - Are empty
fn needs_quoting(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }

    let first_char = name.chars().next().unwrap_or(' ');
    if first_char.is_uppercase() || first_char.is_ascii_digit() {
        return true;
    }

    !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@')
}

/// Try to interpret a list of terms as a charlist (string).
///
/// Returns Some(String) if all elements are integers in the printable Latin-1 range,
/// None otherwise.
fn try_as_charlist(elements: &[Term]) -> Option<String> {
    let mut chars = Vec::with_capacity(elements.len());

    for element in elements {
        let code = match element {
            Term::FixInteger(i) => i.value as i64,
            Term::BigInteger(i) => {
                // Big integers outside i64 range can't be valid chars
                i.value.clone().try_into().ok()?
            }
            _ => return None,
        };

        // Check if it's a valid printable Latin-1 character
        // Allow printable ASCII (32-126), newline (10), tab (9), carriage return (13)
        if !(code == 9 || code == 10 || code == 13 || (32..=126).contains(&code)) {
            return None;
        }

        chars.push(code as u8 as char);
    }

    // Only treat as charlist if non-empty
    if chars.is_empty() {
        return None;
    }

    Some(chars.into_iter().collect())
}

/// Escape special characters in a string for Erlang syntax.
fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

/// Determine if a collection should be formatted on multiple lines.
///
/// Uses multiline format when:
/// - More than 5 elements
/// - Any element is a nested collection (tuple, list, map)
fn should_format_multiline(elements: &[Term]) -> bool {
    if elements.len() > 5 {
        return true;
    }

    elements
        .iter()
        .any(|e| matches!(e, Term::Tuple(_) | Term::List(_) | Term::Map(_)))
}

/// Format a module name in Elixir style.
///
/// If the atom name starts with "Elixir.", strip that prefix and return the rest.
/// Otherwise return the name unchanged.
fn format_module_name(name: &str) -> String {
    if let Some(stripped) = name.strip_prefix("Elixir.") {
        stripped.to_string()
    } else {
        name.to_string()
    }
}

/// Check if a list is a keyword list.
///
/// A keyword list is a list where every element is a 2-tuple with an atom as the first element.
fn is_keyword_list(elements: &[Term]) -> bool {
    if elements.is_empty() {
        return false;
    }

    elements.iter().all(|term| {
        if let Term::Tuple(t) = term
            && t.elements.len() == 2
            && matches!(t.elements[0], Term::Atom(_))
        {
            true
        } else {
            false
        }
    })
}

/// Extract the struct name from a map's entries if it has a __struct__ key.
///
/// Returns Some(struct_name) if __struct__ key is present with an atom value,
/// None otherwise.
fn extract_struct_name(entries: &[(Term, Term)]) -> Option<String> {
    entries.iter().find_map(|(k, v)| {
        if let Term::Atom(key_atom) = k
            && key_atom.name == "__struct__"
            && let Term::Atom(struct_atom) = v
        {
            Some(struct_atom.name.clone())
        } else {
            None
        }
    })
}

/// Check if a term is the __struct__ key.
fn is_struct_key(term: &Term) -> bool {
    if let Term::Atom(a) = term {
        a.name == "__struct__"
    } else {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn get_formatter_returns_correct_type() {
        let erlang = get_formatter(FormatterMode::Erlang);
        let elixir = get_formatter(FormatterMode::Elixir);
        let gleam = get_formatter(FormatterMode::Gleam);
        let lfe = get_formatter(FormatterMode::Lfe);

        // Test that each formatter produces different output for atoms
        assert_eq!(erlang.format_atom("ok"), "ok");
        assert_eq!(elixir.format_atom("ok"), ":ok");
        assert_eq!(gleam.format_atom("ok"), "ok // Note: Erlang-style atom");
        assert_eq!(lfe.format_atom("ok"), "'ok");
    }

    #[test]
    fn needs_quoting_simple_atoms() {
        assert!(!needs_quoting("ok"));
        assert!(!needs_quoting("error"));
        assert!(!needs_quoting("foo_bar"));
        assert!(!needs_quoting("node@host"));
    }

    #[test]
    fn needs_quoting_special_atoms() {
        assert!(needs_quoting("Uppercase"));
        assert!(needs_quoting("123starts_with_digit"));
        assert!(needs_quoting("with-dash"));
        assert!(needs_quoting("with space"));
        assert!(needs_quoting(""));
    }

    #[test]
    fn erlang_format_atom_simple() {
        let formatter = ErlangFormatter;
        assert_eq!(formatter.format_atom("ok"), "ok");
        assert_eq!(formatter.format_atom("error"), "error");
    }

    #[test]
    fn erlang_format_atom_needs_quotes() {
        let formatter = ErlangFormatter;
        assert_eq!(formatter.format_atom("with-dash"), "'with-dash'");
        assert_eq!(formatter.format_atom("Uppercase"), "'Uppercase'");
    }

    #[test]
    fn gleam_format_tuple() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        // Now formats as Result type
        assert_eq!(result, "Ok(42)");
    }

    #[test]
    fn lfe_format_tuple() {
        let formatter = LfeFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "#('ok 42)");
    }

    #[test]
    fn erlang_format_list() {
        let formatter = ErlangFormatter;
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn erlang_format_binary_text() {
        let formatter = ErlangFormatter;
        let result = formatter.format_binary(b"hello");
        assert_eq!(result, "<<\"hello\">>");
    }

    #[test]
    fn erlang_format_binary_raw() {
        let formatter = ErlangFormatter;
        let result = formatter.format_binary(&[1, 2, 255]);
        assert_eq!(result, "<<1,2,255>>");
    }

    // ============================================
    // Comprehensive Erlang formatter tests (US-007)
    // ============================================

    #[test]
    fn erlang_format_atom_with_at_symbol() {
        let formatter = ErlangFormatter;
        assert_eq!(formatter.format_atom("node@host"), "node@host");
    }

    #[test]
    fn erlang_format_atom_empty() {
        let formatter = ErlangFormatter;
        assert_eq!(formatter.format_atom(""), "''");
    }

    #[test]
    fn erlang_format_tuple_empty() {
        let formatter = ErlangFormatter;
        let result = formatter.format_tuple(&[]);
        assert_eq!(result, "{}");
    }

    #[test]
    fn erlang_format_tuple_ok_value() {
        let formatter = ErlangFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "{ok, 42}");
    }

    #[test]
    fn erlang_format_tuple_error() {
        let formatter = ErlangFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Atom::from("not_found")),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "{error, not_found}");
    }

    #[test]
    fn erlang_format_list_empty() {
        let formatter = ErlangFormatter;
        let nil = eetf::List::nil();
        let term = Term::from(nil);
        let result = formatter.format_term(&term);
        assert_eq!(result, "[]");
    }

    #[test]
    fn erlang_format_charlist() {
        let formatter = ErlangFormatter;
        // "hello" as charlist: [104, 101, 108, 108, 111]
        let elements = vec![
            Term::from(eetf::FixInteger::from(104)), // h
            Term::from(eetf::FixInteger::from(101)), // e
            Term::from(eetf::FixInteger::from(108)), // l
            Term::from(eetf::FixInteger::from(108)), // l
            Term::from(eetf::FixInteger::from(111)), // o
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "\"hello\"");
    }

    #[test]
    fn erlang_format_charlist_with_escape() {
        let formatter = ErlangFormatter;
        // "a\nb" as charlist: [97, 10, 98]
        let elements = vec![
            Term::from(eetf::FixInteger::from(97)), // a
            Term::from(eetf::FixInteger::from(10)), // newline
            Term::from(eetf::FixInteger::from(98)), // b
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "\"a\\nb\"");
    }

    #[test]
    fn erlang_format_non_charlist_integers() {
        let formatter = ErlangFormatter;
        // [1, 2, 3] should stay as list, not be treated as charlist (non-printable)
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn erlang_format_map_empty() {
        let formatter = ErlangFormatter;
        let result = formatter.format_map(&[]);
        assert_eq!(result, "#{}");
    }

    #[test]
    fn erlang_format_map_single_entry() {
        let formatter = ErlangFormatter;
        let entries = vec![(
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(42)),
        )];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "#{key => 42}");
    }

    #[test]
    fn erlang_format_map_multiple_entries() {
        let formatter = ErlangFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("a")),
                Term::from(eetf::FixInteger::from(1)),
            ),
            (
                Term::from(eetf::Atom::from("b")),
                Term::from(eetf::FixInteger::from(2)),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "#{a => 1, b => 2}");
    }

    #[test]
    fn erlang_format_pid() {
        let formatter = ErlangFormatter;
        let pid = eetf::Pid {
            node: eetf::Atom::from("nonode@nohost"),
            id: 123,
            serial: 0,
            creation: 0,
        };
        let result = formatter.format_pid(&pid);
        assert_eq!(result, "<nonode@nohost.123.0>");
    }

    #[test]
    fn erlang_format_reference() {
        let formatter = ErlangFormatter;
        let reference = eetf::Reference {
            node: eetf::Atom::from("nonode@nohost"),
            id: vec![123, 456, 789],
            creation: 0,
        };
        let result = formatter.format_reference(&reference);
        assert_eq!(result, "#Ref<nonode@nohost.123.456.789>");
    }

    #[test]
    fn erlang_format_binary_empty() {
        let formatter = ErlangFormatter;
        let result = formatter.format_binary(&[]);
        assert_eq!(result, "<<>>");
    }

    #[test]
    fn erlang_format_integer_positive() {
        let formatter = ErlangFormatter;
        let term = Term::from(eetf::FixInteger::from(42));
        let result = formatter.format_term(&term);
        assert_eq!(result, "42");
    }

    #[test]
    fn erlang_format_integer_negative() {
        let formatter = ErlangFormatter;
        let term = Term::from(eetf::FixInteger::from(-42));
        let result = formatter.format_term(&term);
        assert_eq!(result, "-42");
    }

    #[test]
    fn erlang_format_float() {
        let formatter = ErlangFormatter;
        let term = Term::from(eetf::Float { value: 42.5 });
        let result = formatter.format_term(&term);
        assert!(result.starts_with("42.5")); // Float formatting may vary
    }

    #[test]
    fn erlang_format_nested_tuple_in_list() {
        let formatter = ErlangFormatter;
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(1)),
        ]);
        let elements = vec![Term::from(tuple)];
        let result = formatter.format_list(&elements);
        // Should use multiline because list contains a tuple
        assert!(result.contains("{ok, 1}"));
    }

    #[test]
    fn erlang_format_nested_deeply() {
        use std::collections::HashMap;

        let formatter = ErlangFormatter;

        // Create: {ok, #{data => [1, 2, 3]}}
        let inner_list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ]);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(Term::from(eetf::Atom::from("data")), Term::from(inner_list));
        let map = eetf::Map::from(map_data);
        let outer_tuple =
            eetf::Tuple::from(vec![Term::from(eetf::Atom::from("ok")), Term::from(map)]);

        let term = Term::from(outer_tuple);
        let result = formatter.format_term(&term);

        // Should contain the nested structure
        assert!(result.contains("ok"));
        assert!(result.contains("data"));
        assert!(result.contains("=>"));
    }

    #[test]
    fn try_as_charlist_valid_string() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(104)), // h
            Term::from(eetf::FixInteger::from(105)), // i
        ];
        assert_eq!(try_as_charlist(&elements), Some("hi".to_string()));
    }

    #[test]
    fn try_as_charlist_with_whitespace() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(104)), // h
            Term::from(eetf::FixInteger::from(32)),  // space
            Term::from(eetf::FixInteger::from(105)), // i
        ];
        assert_eq!(try_as_charlist(&elements), Some("h i".to_string()));
    }

    #[test]
    fn try_as_charlist_with_tab() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(97)), // a
            Term::from(eetf::FixInteger::from(9)),  // tab
            Term::from(eetf::FixInteger::from(98)), // b
        ];
        assert_eq!(try_as_charlist(&elements), Some("a\tb".to_string()));
    }

    #[test]
    fn try_as_charlist_empty() {
        let elements: Vec<Term> = vec![];
        assert_eq!(try_as_charlist(&elements), None);
    }

    #[test]
    fn try_as_charlist_non_printable() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)), // non-printable
            Term::from(eetf::FixInteger::from(2)),
        ];
        assert_eq!(try_as_charlist(&elements), None);
    }

    #[test]
    fn try_as_charlist_mixed_types() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(104)),
            Term::from(eetf::Atom::from("not_an_int")),
        ];
        assert_eq!(try_as_charlist(&elements), None);
    }

    #[test]
    fn escape_string_basic() {
        assert_eq!(escape_string("hello"), "hello");
    }

    #[test]
    fn escape_string_with_newline() {
        assert_eq!(escape_string("a\nb"), "a\\nb");
    }

    #[test]
    fn escape_string_with_quote() {
        assert_eq!(escape_string("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn escape_string_with_backslash() {
        assert_eq!(escape_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_string_with_tab_and_carriage_return() {
        assert_eq!(escape_string("a\t\rb"), "a\\t\\rb");
    }

    #[test]
    fn should_format_multiline_few_elements() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
        ];
        assert!(!should_format_multiline(&elements));
    }

    #[test]
    fn should_format_multiline_many_elements() {
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
            Term::from(eetf::FixInteger::from(4)),
            Term::from(eetf::FixInteger::from(5)),
            Term::from(eetf::FixInteger::from(6)),
        ];
        assert!(should_format_multiline(&elements));
    }

    #[test]
    fn should_format_multiline_with_nested_tuple() {
        let tuple = eetf::Tuple::from(vec![Term::from(eetf::Atom::from("ok"))]);
        let elements = vec![Term::from(tuple)];
        assert!(should_format_multiline(&elements));
    }

    #[test]
    fn should_format_multiline_with_nested_list() {
        let list = eetf::List::from(vec![Term::from(eetf::FixInteger::from(1))]);
        let elements = vec![Term::from(list)];
        assert!(should_format_multiline(&elements));
    }

    #[test]
    fn should_format_multiline_with_nested_map() {
        use std::collections::HashMap;

        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(1)),
        );
        let map = eetf::Map::from(map_data);
        let elements = vec![Term::from(map)];
        assert!(should_format_multiline(&elements));
    }

    #[test]
    fn erlang_format_full_term_atom() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let term = Term::from(eetf::Atom::from("ok"));
        assert_eq!(formatter.format_term(&term), "ok");
    }

    #[test]
    fn erlang_format_full_term_tuple() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "{ok, 42}");
    }

    #[test]
    fn erlang_format_full_term_list() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "[1, 2, 3]");
    }

    #[test]
    fn erlang_format_full_term_binary() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let binary = eetf::Binary::from(b"hello".to_vec());
        let term = Term::from(binary);
        assert_eq!(formatter.format_term(&term), "<<\"hello\">>");
    }

    #[test]
    fn erlang_format_full_term_map() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Erlang);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(42)),
        );
        let map = eetf::Map::from(map_data);
        let term = Term::from(map);
        assert_eq!(formatter.format_term(&term), "#{key => 42}");
    }

    #[test]
    fn erlang_format_full_term_pid() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let pid = eetf::Pid {
            node: eetf::Atom::from("nonode@nohost"),
            id: 100,
            serial: 0,
            creation: 0,
        };
        let term = Term::from(pid);
        assert_eq!(formatter.format_term(&term), "<nonode@nohost.100.0>");
    }

    #[test]
    fn erlang_format_full_term_reference() {
        let formatter = get_formatter(FormatterMode::Erlang);
        let reference = eetf::Reference {
            node: eetf::Atom::from("nonode@nohost"),
            id: vec![1, 2, 3],
            creation: 0,
        };
        let term = Term::from(reference);
        assert_eq!(formatter.format_term(&term), "#Ref<nonode@nohost.1.2.3>");
    }

    // ============================================
    // Comprehensive Elixir formatter tests (US-008)
    // ============================================

    #[test]
    fn elixir_format_atom_simple() {
        let formatter = ElixirFormatter;
        assert_eq!(formatter.format_atom("ok"), ":ok");
        assert_eq!(formatter.format_atom("error"), ":error");
    }

    #[test]
    fn elixir_format_atom_needs_quotes() {
        let formatter = ElixirFormatter;
        assert_eq!(formatter.format_atom("with-dash"), ":\"with-dash\"");
        assert_eq!(formatter.format_atom("with space"), ":\"with space\"");
    }

    #[test]
    fn elixir_format_atom_module() {
        let formatter = ElixirFormatter;
        assert_eq!(formatter.format_atom("Elixir.MyModule"), "MyModule");
        assert_eq!(
            formatter.format_atom("Elixir.My.Nested.Module"),
            "My.Nested.Module"
        );
    }

    #[test]
    fn elixir_format_atom_module_in_term() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let term = Term::from(eetf::Atom::from("Elixir.Phoenix.Socket"));
        assert_eq!(formatter.format_term(&term), "Phoenix.Socket");
    }

    #[test]
    fn elixir_format_tuple_ok_value() {
        let formatter = ElixirFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "{:ok, 42}");
    }

    #[test]
    fn elixir_format_tuple_error() {
        let formatter = ElixirFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Atom::from("not_found")),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "{:error, :not_found}");
    }

    #[test]
    fn elixir_format_list_integers() {
        let formatter = ElixirFormatter;
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn elixir_format_list_empty() {
        let formatter = ElixirFormatter;
        let nil = eetf::List::nil();
        let term = Term::from(nil);
        let result = formatter.format_term(&term);
        assert_eq!(result, "[]");
    }

    #[test]
    fn elixir_format_charlist() {
        let formatter = ElixirFormatter;
        // "hello" as charlist: [104, 101, 108, 108, 111]
        let elements = vec![
            Term::from(eetf::FixInteger::from(104)), // h
            Term::from(eetf::FixInteger::from(101)), // e
            Term::from(eetf::FixInteger::from(108)), // l
            Term::from(eetf::FixInteger::from(108)), // l
            Term::from(eetf::FixInteger::from(111)), // o
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "~c\"hello\"");
    }

    #[test]
    fn elixir_format_charlist_with_escape() {
        let formatter = ElixirFormatter;
        // "a\nb" as charlist
        let elements = vec![
            Term::from(eetf::FixInteger::from(97)), // a
            Term::from(eetf::FixInteger::from(10)), // newline
            Term::from(eetf::FixInteger::from(98)), // b
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "~c\"a\\nb\"");
    }

    #[test]
    fn elixir_format_keyword_list() {
        let formatter = ElixirFormatter;
        let elements = vec![
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("name")),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ])),
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("age")),
                Term::from(eetf::FixInteger::from(30)),
            ])),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[name: \"Alice\", age: 30]");
    }

    #[test]
    fn elixir_format_keyword_list_single_item() {
        let formatter = ElixirFormatter;
        let elements = vec![Term::from(eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::Atom::from("value")),
        ]))];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[key: :value]");
    }

    #[test]
    fn elixir_format_binary_text() {
        let formatter = ElixirFormatter;
        let result = formatter.format_binary(b"hello");
        assert_eq!(result, "\"hello\"");
    }

    #[test]
    fn elixir_format_binary_empty() {
        let formatter = ElixirFormatter;
        let result = formatter.format_binary(&[]);
        assert_eq!(result, "\"\"");
    }

    #[test]
    fn elixir_format_binary_raw() {
        let formatter = ElixirFormatter;
        let result = formatter.format_binary(&[1, 2, 255]);
        assert_eq!(result, "<<1, 2, 255>>");
    }

    #[test]
    fn elixir_format_binary_with_escapes() {
        let formatter = ElixirFormatter;
        let result = formatter.format_binary(b"hello\nworld");
        assert_eq!(result, "\"hello\\nworld\"");
    }

    #[test]
    fn elixir_format_map_atom_keys() {
        let formatter = ElixirFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("name")),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ),
            (
                Term::from(eetf::Atom::from("age")),
                Term::from(eetf::FixInteger::from(30)),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "%{name: \"Alice\", age: 30}");
    }

    #[test]
    fn elixir_format_map_string_keys() {
        let formatter = ElixirFormatter;
        let entries = vec![
            (
                Term::from(eetf::Binary::from(b"name".to_vec())),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ),
            (
                Term::from(eetf::Binary::from(b"age".to_vec())),
                Term::from(eetf::FixInteger::from(30)),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "%{\"name\" => \"Alice\", \"age\" => 30}");
    }

    #[test]
    fn elixir_format_map_mixed_keys() {
        let formatter = ElixirFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("atom_key")),
                Term::from(eetf::FixInteger::from(1)),
            ),
            (
                Term::from(eetf::Binary::from(b"string_key".to_vec())),
                Term::from(eetf::FixInteger::from(2)),
            ),
        ];
        let result = formatter.format_map(&entries);
        // When keys are mixed types, use => syntax for all
        assert_eq!(result, "%{:atom_key => 1, \"string_key\" => 2}");
    }

    #[test]
    fn elixir_format_map_empty() {
        let formatter = ElixirFormatter;
        let result = formatter.format_map(&[]);
        assert_eq!(result, "%{}");
    }

    #[test]
    fn elixir_format_struct_simple() {
        let formatter = ElixirFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("__struct__")),
                Term::from(eetf::Atom::from("Elixir.User")),
            ),
            (
                Term::from(eetf::Atom::from("name")),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ),
            (
                Term::from(eetf::Atom::from("age")),
                Term::from(eetf::FixInteger::from(30)),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "%User{name: \"Alice\", age: 30}");
    }

    #[test]
    fn elixir_format_struct_nested_module() {
        let formatter = ElixirFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("__struct__")),
                Term::from(eetf::Atom::from("Elixir.MyApp.User")),
            ),
            (
                Term::from(eetf::Atom::from("id")),
                Term::from(eetf::FixInteger::from(123)),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "%MyApp.User{id: 123}");
    }

    #[test]
    fn elixir_format_struct_empty() {
        let formatter = ElixirFormatter;
        let entries = vec![(
            Term::from(eetf::Atom::from("__struct__")),
            Term::from(eetf::Atom::from("Elixir.Empty")),
        )];
        let result = formatter.format_map(&entries);
        assert_eq!(result, "%Empty{}");
    }

    #[test]
    fn elixir_format_pid() {
        let formatter = ElixirFormatter;
        let pid = eetf::Pid {
            node: eetf::Atom::from("nonode@nohost"),
            id: 123,
            serial: 0,
            creation: 0,
        };
        let result = formatter.format_pid(&pid);
        assert_eq!(result, "#PID<nonode@nohost.123.0>");
    }

    #[test]
    fn elixir_format_reference() {
        let formatter = ElixirFormatter;
        let reference = eetf::Reference {
            node: eetf::Atom::from("nonode@nohost"),
            id: vec![0, 123, 456],
            creation: 0,
        };
        let result = formatter.format_reference(&reference);
        assert_eq!(result, "#Reference<nonode@nohost.0.123.456>");
    }

    #[test]
    fn elixir_format_full_term_atom() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let term = Term::from(eetf::Atom::from("ok"));
        assert_eq!(formatter.format_term(&term), ":ok");
    }

    #[test]
    fn elixir_format_full_term_integer() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let term = Term::from(eetf::FixInteger::from(42));
        assert_eq!(formatter.format_term(&term), "42");
    }

    #[test]
    fn elixir_format_full_term_float() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let term = Term::from(eetf::Float { value: 42.5 });
        assert!(formatter.format_term(&term).starts_with("42.5"));
    }

    #[test]
    fn elixir_format_full_term_binary() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let binary = eetf::Binary::from(b"hello".to_vec());
        let term = Term::from(binary);
        assert_eq!(formatter.format_term(&term), "\"hello\"");
    }

    #[test]
    fn elixir_format_full_term_tuple() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "{:ok, 42}");
    }

    #[test]
    fn elixir_format_full_term_list() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "[1, 2, 3]");
    }

    #[test]
    fn elixir_format_full_term_keyword_list() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let list = eetf::List::from(vec![
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("name")),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ])),
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("age")),
                Term::from(eetf::FixInteger::from(30)),
            ])),
        ]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "[name: \"Alice\", age: 30]");
    }

    #[test]
    fn elixir_format_full_term_map() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Elixir);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(42)),
        );
        let map = eetf::Map::from(map_data);
        let term = Term::from(map);
        assert_eq!(formatter.format_term(&term), "%{key: 42}");
    }

    #[test]
    fn elixir_format_full_term_struct() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Elixir);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("__struct__")),
            Term::from(eetf::Atom::from("Elixir.User")),
        );
        map_data.insert(
            Term::from(eetf::Atom::from("name")),
            Term::from(eetf::Binary::from(b"Alice".to_vec())),
        );
        let map = eetf::Map::from(map_data);
        let term = Term::from(map);
        assert_eq!(formatter.format_term(&term), "%User{name: \"Alice\"}");
    }

    #[test]
    fn elixir_format_full_term_pid() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let pid = eetf::Pid {
            node: eetf::Atom::from("node@host"),
            id: 100,
            serial: 0,
            creation: 0,
        };
        let term = Term::from(pid);
        assert_eq!(formatter.format_term(&term), "#PID<node@host.100.0>");
    }

    #[test]
    fn elixir_format_full_term_reference() {
        let formatter = get_formatter(FormatterMode::Elixir);
        let reference = eetf::Reference {
            node: eetf::Atom::from("node@host"),
            id: vec![1, 2, 3],
            creation: 0,
        };
        let term = Term::from(reference);
        assert_eq!(formatter.format_term(&term), "#Reference<node@host.1.2.3>");
    }

    #[test]
    fn is_keyword_list_valid() {
        let elements = vec![
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("key1")),
                Term::from(eetf::FixInteger::from(1)),
            ])),
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("key2")),
                Term::from(eetf::FixInteger::from(2)),
            ])),
        ];
        assert!(is_keyword_list(&elements));
    }

    #[test]
    fn is_keyword_list_empty() {
        let elements: Vec<Term> = vec![];
        assert!(!is_keyword_list(&elements));
    }

    #[test]
    fn is_keyword_list_wrong_tuple_size() {
        let elements = vec![Term::from(eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)), // 3 elements
        ]))];
        assert!(!is_keyword_list(&elements));
    }

    #[test]
    fn is_keyword_list_non_atom_key() {
        let elements = vec![Term::from(eetf::Tuple::from(vec![
            Term::from(eetf::FixInteger::from(123)), // Not an atom
            Term::from(eetf::FixInteger::from(1)),
        ]))];
        assert!(!is_keyword_list(&elements));
    }

    #[test]
    fn is_keyword_list_not_all_tuples() {
        let elements = vec![
            Term::from(eetf::Tuple::from(vec![
                Term::from(eetf::Atom::from("key")),
                Term::from(eetf::FixInteger::from(1)),
            ])),
            Term::from(eetf::FixInteger::from(2)), // Not a tuple
        ];
        assert!(!is_keyword_list(&elements));
    }

    #[test]
    fn extract_struct_name_valid() {
        let entries = vec![
            (
                Term::from(eetf::Atom::from("__struct__")),
                Term::from(eetf::Atom::from("Elixir.MyModule")),
            ),
            (
                Term::from(eetf::Atom::from("field")),
                Term::from(eetf::FixInteger::from(42)),
            ),
        ];
        assert_eq!(
            extract_struct_name(&entries),
            Some("Elixir.MyModule".to_string())
        );
    }

    #[test]
    fn extract_struct_name_none() {
        let entries = vec![(
            Term::from(eetf::Atom::from("field")),
            Term::from(eetf::FixInteger::from(42)),
        )];
        assert_eq!(extract_struct_name(&entries), None);
    }

    #[test]
    fn format_module_name_with_prefix() {
        assert_eq!(format_module_name("Elixir.MyModule"), "MyModule");
        assert_eq!(
            format_module_name("Elixir.My.Nested.Module"),
            "My.Nested.Module"
        );
    }

    #[test]
    fn format_module_name_without_prefix() {
        assert_eq!(format_module_name("my_atom"), "my_atom");
        assert_eq!(format_module_name("ok"), "ok");
    }

    #[test]
    fn is_struct_key_true() {
        let term = Term::from(eetf::Atom::from("__struct__"));
        assert!(is_struct_key(&term));
    }

    #[test]
    fn is_struct_key_false() {
        let term = Term::from(eetf::Atom::from("other_key"));
        assert!(!is_struct_key(&term));
    }

    #[test]
    fn is_struct_key_non_atom() {
        let term = Term::from(eetf::FixInteger::from(123));
        assert!(!is_struct_key(&term));
    }

    // ============================================
    // Comprehensive Gleam formatter tests (US-009)
    // ============================================

    #[test]
    fn gleam_format_atom_simple() {
        let formatter = GleamFormatter;
        assert_eq!(formatter.format_atom("ok"), "ok // Note: Erlang-style atom");
        assert_eq!(
            formatter.format_atom("error"),
            "error // Note: Erlang-style atom"
        );
    }

    #[test]
    fn gleam_format_atom_needs_quotes() {
        let formatter = GleamFormatter;
        assert_eq!(
            formatter.format_atom("with-dash"),
            "'with-dash' // Note: Erlang-style atom"
        );
        assert_eq!(
            formatter.format_atom("with space"),
            "'with space' // Note: Erlang-style atom"
        );
    }

    #[test]
    fn gleam_format_tuple_ok() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "Ok(42)");
    }

    #[test]
    fn gleam_format_tuple_ok_with_nested() {
        let formatter = GleamFormatter;
        let inner_tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("data")),
            Term::from(eetf::FixInteger::from(123)),
        ]);
        let elements = vec![Term::from(eetf::Atom::from("ok")), Term::from(inner_tuple)];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "Ok(#(data // Note: Erlang-style atom, 123))");
    }

    #[test]
    fn gleam_format_tuple_error() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Atom::from("not_found")),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "Error(not_found // Note: Erlang-style atom)");
    }

    #[test]
    fn gleam_format_tuple_error_with_string() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Binary::from(b"not found".to_vec())),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "Error(\"not found\")");
    }

    #[test]
    fn gleam_format_tuple_regular() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("data")),
            Term::from(eetf::FixInteger::from(42)),
            Term::from(eetf::FixInteger::from(100)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "#(data // Note: Erlang-style atom, 42, 100)");
    }

    #[test]
    fn gleam_format_tuple_empty() {
        let formatter = GleamFormatter;
        let result = formatter.format_tuple(&[]);
        assert_eq!(result, "#()");
    }

    #[test]
    fn gleam_format_list_integers() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn gleam_format_list_empty() {
        let formatter = GleamFormatter;
        let nil = eetf::List::nil();
        let term = Term::from(nil);
        let result = formatter.format_term(&term);
        assert_eq!(result, "[]");
    }

    #[test]
    fn gleam_format_binary_text() {
        let formatter = GleamFormatter;
        let result = formatter.format_binary(b"hello");
        assert_eq!(result, "\"hello\"");
    }

    #[test]
    fn gleam_format_binary_empty() {
        let formatter = GleamFormatter;
        let result = formatter.format_binary(&[]);
        assert_eq!(result, "\"\"");
    }

    #[test]
    fn gleam_format_binary_raw_bytes() {
        let formatter = GleamFormatter;
        let result = formatter.format_binary(&[1, 2, 255]);
        assert_eq!(result, "<<1, 2, 255>>");
    }

    #[test]
    fn gleam_format_binary_with_escapes() {
        let formatter = GleamFormatter;
        let result = formatter.format_binary(b"hello\nworld");
        assert_eq!(result, "\"hello\\nworld\"");
    }

    #[test]
    fn gleam_format_map_simple() {
        let formatter = GleamFormatter;
        let entries = vec![
            (
                Term::from(eetf::Binary::from(b"key".to_vec())),
                Term::from(eetf::FixInteger::from(42)),
            ),
            (
                Term::from(eetf::Binary::from(b"name".to_vec())),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ),
        ];
        let result = formatter.format_map(&entries);
        assert_eq!(
            result,
            "dict.from_list([#(\"key\", 42), #(\"name\", \"Alice\")])"
        );
    }

    #[test]
    fn gleam_format_map_empty() {
        let formatter = GleamFormatter;
        let result = formatter.format_map(&[]);
        assert_eq!(result, "dict.from_list([])");
    }

    #[test]
    fn gleam_format_pid() {
        let formatter = GleamFormatter;
        let pid = eetf::Pid {
            node: eetf::Atom::from("node@host"),
            id: 123,
            serial: 456,
            creation: 0,
        };
        let result = formatter.format_pid(&pid);
        assert_eq!(result, "//pid<node@host.123.456>");
    }

    #[test]
    fn gleam_format_reference() {
        let formatter = GleamFormatter;
        let reference = eetf::Reference {
            node: eetf::Atom::from("node@host"),
            id: vec![0, 123, 456, 789],
            creation: 0,
        };
        let result = formatter.format_reference(&reference);
        assert_eq!(result, "//ref<node@host.0.123.456.789>");
    }

    #[test]
    fn gleam_format_full_term_integer() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let term = Term::from(eetf::FixInteger::from(42));
        assert_eq!(formatter.format_term(&term), "42");
    }

    #[test]
    fn gleam_format_full_term_negative_integer() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let term = Term::from(eetf::FixInteger::from(-100));
        assert_eq!(formatter.format_term(&term), "-100");
    }

    #[test]
    fn gleam_format_full_term_float() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let term = Term::from(eetf::Float { value: 42.5 });
        assert!(formatter.format_term(&term).starts_with("42.5"));
    }

    #[test]
    fn gleam_format_full_term_binary() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let binary = eetf::Binary::from(b"hello world".to_vec());
        let term = Term::from(binary);
        assert_eq!(formatter.format_term(&term), "\"hello world\"");
    }

    #[test]
    fn gleam_format_full_term_ok_tuple() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::Binary::from(b"success".to_vec())),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "Ok(\"success\")");
    }

    #[test]
    fn gleam_format_full_term_error_tuple() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Atom::from("timeout")),
        ]);
        let term = Term::from(tuple);
        assert_eq!(
            formatter.format_term(&term),
            "Error(timeout // Note: Erlang-style atom)"
        );
    }

    #[test]
    fn gleam_format_full_term_regular_tuple() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "#(1, 2, 3)");
    }

    #[test]
    fn gleam_format_full_term_list() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(10)),
            Term::from(eetf::FixInteger::from(20)),
            Term::from(eetf::FixInteger::from(30)),
        ]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "[10, 20, 30]");
    }

    #[test]
    fn gleam_format_full_term_map() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Gleam);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Binary::from(b"key1".to_vec())),
            Term::from(eetf::FixInteger::from(100)),
        );
        map_data.insert(
            Term::from(eetf::Binary::from(b"key2".to_vec())),
            Term::from(eetf::FixInteger::from(200)),
        );
        let map = eetf::Map::from(map_data);
        let term = Term::from(map);
        let result = formatter.format_term(&term);
        // Maps are unordered, so we check for both possible orderings
        assert!(
            result == "dict.from_list([#(\"key1\", 100), #(\"key2\", 200)])"
                || result == "dict.from_list([#(\"key2\", 200), #(\"key1\", 100)])"
        );
    }

    #[test]
    fn gleam_format_full_term_pid() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let pid = eetf::Pid {
            node: eetf::Atom::from("gleam@localhost"),
            id: 42,
            serial: 7,
            creation: 0,
        };
        let term = Term::from(pid);
        assert_eq!(formatter.format_term(&term), "//pid<gleam@localhost.42.7>");
    }

    #[test]
    fn gleam_format_full_term_reference() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let reference = eetf::Reference {
            node: eetf::Atom::from("gleam@localhost"),
            id: vec![1, 2, 3],
            creation: 0,
        };
        let term = Term::from(reference);
        assert_eq!(formatter.format_term(&term), "//ref<gleam@localhost.1.2.3>");
    }

    #[test]
    fn gleam_format_nested_ok_with_list() {
        let formatter = get_formatter(FormatterMode::Gleam);
        let inner_list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
        ]);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(inner_list),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "Ok([1, 2])");
    }

    #[test]
    fn gleam_format_nested_error_with_map() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Gleam);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Binary::from(b"code".to_vec())),
            Term::from(eetf::FixInteger::from(404)),
        );
        let map = eetf::Map::from(map_data);
        let tuple = eetf::Tuple::from(vec![Term::from(eetf::Atom::from("error")), Term::from(map)]);
        let term = Term::from(tuple);
        assert_eq!(
            formatter.format_term(&term),
            "Error(dict.from_list([#(\"code\", 404)]))"
        );
    }

    #[test]
    fn gleam_try_format_result_tuple_ok() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(123)),
        ];
        assert_eq!(
            formatter.try_format_result_tuple(&elements),
            Some("Ok(123)".to_string())
        );
    }

    #[test]
    fn gleam_try_format_result_tuple_error() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("error")),
            Term::from(eetf::Atom::from("bad")),
        ];
        assert_eq!(
            formatter.try_format_result_tuple(&elements),
            Some("Error(bad // Note: Erlang-style atom)".to_string())
        );
    }

    #[test]
    fn gleam_try_format_result_tuple_not_result() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("data")),
            Term::from(eetf::FixInteger::from(123)),
        ];
        assert_eq!(formatter.try_format_result_tuple(&elements), None);
    }

    #[test]
    fn gleam_try_format_result_tuple_wrong_size() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
        ];
        assert_eq!(formatter.try_format_result_tuple(&elements), None);
    }

    #[test]
    fn gleam_try_format_result_tuple_non_atom_tag() {
        let formatter = GleamFormatter;
        let elements = vec![
            Term::from(eetf::FixInteger::from(123)),
            Term::from(eetf::FixInteger::from(456)),
        ];
        assert_eq!(formatter.try_format_result_tuple(&elements), None);
    }

    // ============================================
    // Comprehensive LFE formatter tests (US-010)
    // ============================================

    #[test]
    fn lfe_format_atom_simple() {
        let formatter = LfeFormatter;
        assert_eq!(formatter.format_atom("ok"), "'ok");
        assert_eq!(formatter.format_atom("error"), "'error");
        assert_eq!(formatter.format_atom("foo_bar"), "'foo_bar");
    }

    #[test]
    fn lfe_format_atom_with_spaces() {
        let formatter = LfeFormatter;
        assert_eq!(formatter.format_atom("with space"), "'|with space|");
        assert_eq!(formatter.format_atom("hello world"), "'|hello world|");
    }

    #[test]
    fn lfe_format_atom_with_pipe() {
        let formatter = LfeFormatter;
        assert_eq!(formatter.format_atom("has|pipe"), "'|has|pipe|");
    }

    #[test]
    fn lfe_format_atom_empty() {
        let formatter = LfeFormatter;
        assert_eq!(formatter.format_atom(""), "'||");
    }

    #[test]
    fn lfe_format_tuple_simple() {
        let formatter = LfeFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "#('ok 42)");
    }

    #[test]
    fn lfe_format_tuple_three_elements() {
        let formatter = LfeFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("a")),
            Term::from(eetf::Atom::from("b")),
            Term::from(eetf::Atom::from("c")),
        ];
        let result = formatter.format_tuple(&elements);
        assert_eq!(result, "#('a 'b 'c)");
    }

    #[test]
    fn lfe_format_tuple_empty() {
        let formatter = LfeFormatter;
        let result = formatter.format_tuple(&[]);
        assert_eq!(result, "#()");
    }

    #[test]
    fn lfe_format_list_integers() {
        let formatter = LfeFormatter;
        let elements = vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "'(1 2 3)");
    }

    #[test]
    fn lfe_format_list_empty() {
        let formatter = LfeFormatter;
        let nil = eetf::List::nil();
        let term = Term::from(nil);
        let result = formatter.format_term(&term);
        assert_eq!(result, "()");
    }

    #[test]
    fn lfe_format_list_mixed() {
        let formatter = LfeFormatter;
        let elements = vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::Binary::from(b"test".to_vec())),
        ];
        let result = formatter.format_list(&elements);
        assert_eq!(result, "'('ok 1 \"test\")");
    }

    #[test]
    fn lfe_format_binary_text() {
        let formatter = LfeFormatter;
        let result = formatter.format_binary(b"hello");
        assert_eq!(result, "\"hello\"");
    }

    #[test]
    fn lfe_format_binary_empty() {
        let formatter = LfeFormatter;
        let result = formatter.format_binary(&[]);
        assert_eq!(result, "\"\"");
    }

    #[test]
    fn lfe_format_binary_raw_bytes() {
        let formatter = LfeFormatter;
        let result = formatter.format_binary(&[1, 2, 255]);
        assert_eq!(result, "#B(1 2 255)");
    }

    #[test]
    fn lfe_format_binary_with_escapes() {
        let formatter = LfeFormatter;
        let result = formatter.format_binary(b"hello\nworld");
        assert_eq!(result, "\"hello\\nworld\"");
    }

    #[test]
    fn lfe_format_map_simple() {
        let formatter = LfeFormatter;
        let entries = vec![
            (
                Term::from(eetf::Atom::from("key")),
                Term::from(eetf::FixInteger::from(42)),
            ),
            (
                Term::from(eetf::Atom::from("name")),
                Term::from(eetf::Binary::from(b"Alice".to_vec())),
            ),
        ];
        let result = formatter.format_map(&entries);
        // Map entries are unordered
        assert!(result == "#m('key 42 'name \"Alice\")" || result == "#m('name \"Alice\" 'key 42)");
    }

    #[test]
    fn lfe_format_map_empty() {
        let formatter = LfeFormatter;
        let result = formatter.format_map(&[]);
        assert_eq!(result, "#m()");
    }

    #[test]
    fn lfe_format_pid() {
        let formatter = LfeFormatter;
        let pid = eetf::Pid {
            node: eetf::Atom::from("nonode@nohost"),
            id: 123,
            serial: 0,
            creation: 0,
        };
        let result = formatter.format_pid(&pid);
        assert_eq!(result, "#Pid<nonode@nohost.123.0>");
    }

    #[test]
    fn lfe_format_reference() {
        let formatter = LfeFormatter;
        let reference = eetf::Reference {
            node: eetf::Atom::from("nonode@nohost"),
            id: vec![0, 123, 456, 789],
            creation: 0,
        };
        let result = formatter.format_reference(&reference);
        assert_eq!(result, "#Ref<nonode@nohost.0.123.456.789>");
    }

    #[test]
    fn lfe_format_full_term_atom() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let term = Term::from(eetf::Atom::from("ok"));
        assert_eq!(formatter.format_term(&term), "'ok");
    }

    #[test]
    fn lfe_format_full_term_integer() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let term = Term::from(eetf::FixInteger::from(42));
        assert_eq!(formatter.format_term(&term), "42");
    }

    #[test]
    fn lfe_format_full_term_negative_integer() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let term = Term::from(eetf::FixInteger::from(-100));
        assert_eq!(formatter.format_term(&term), "-100");
    }

    #[test]
    fn lfe_format_full_term_float() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let term = Term::from(eetf::Float { value: 42.5 });
        assert!(formatter.format_term(&term).starts_with("42.5"));
    }

    #[test]
    fn lfe_format_full_term_binary() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let binary = eetf::Binary::from(b"hello world".to_vec());
        let term = Term::from(binary);
        assert_eq!(formatter.format_term(&term), "\"hello world\"");
    }

    #[test]
    fn lfe_format_full_term_tuple() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(42)),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "#('ok 42)");
    }

    #[test]
    fn lfe_format_full_term_list() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
            Term::from(eetf::FixInteger::from(3)),
        ]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "'(1 2 3)");
    }

    #[test]
    fn lfe_format_full_term_map() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Lfe);
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("key")),
            Term::from(eetf::FixInteger::from(42)),
        );
        let map = eetf::Map::from(map_data);
        let term = Term::from(map);
        assert_eq!(formatter.format_term(&term), "#m('key 42)");
    }

    #[test]
    fn lfe_format_full_term_pid() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let pid = eetf::Pid {
            node: eetf::Atom::from("lfe@localhost"),
            id: 100,
            serial: 5,
            creation: 0,
        };
        let term = Term::from(pid);
        assert_eq!(formatter.format_term(&term), "#Pid<lfe@localhost.100.5>");
    }

    #[test]
    fn lfe_format_full_term_reference() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let reference = eetf::Reference {
            node: eetf::Atom::from("lfe@localhost"),
            id: vec![1, 2, 3],
            creation: 0,
        };
        let term = Term::from(reference);
        assert_eq!(formatter.format_term(&term), "#Ref<lfe@localhost.1.2.3>");
    }

    #[test]
    fn lfe_format_nested_tuple_in_list() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("ok")),
            Term::from(eetf::FixInteger::from(1)),
        ]);
        let list = eetf::List::from(vec![Term::from(tuple)]);
        let term = Term::from(list);
        assert_eq!(formatter.format_term(&term), "'(#('ok 1))");
    }

    #[test]
    fn lfe_format_nested_list_in_tuple() {
        let formatter = get_formatter(FormatterMode::Lfe);
        let inner_list = eetf::List::from(vec![
            Term::from(eetf::FixInteger::from(1)),
            Term::from(eetf::FixInteger::from(2)),
        ]);
        let tuple = eetf::Tuple::from(vec![
            Term::from(eetf::Atom::from("data")),
            Term::from(inner_list),
        ]);
        let term = Term::from(tuple);
        assert_eq!(formatter.format_term(&term), "#('data '(1 2))");
    }

    #[test]
    fn lfe_format_complex_nested_structure() {
        use std::collections::HashMap;

        let formatter = get_formatter(FormatterMode::Lfe);

        // Create: #('ok #m('status 'success 'count 3))
        let mut map_data: HashMap<Term, Term> = HashMap::new();
        map_data.insert(
            Term::from(eetf::Atom::from("status")),
            Term::from(eetf::Atom::from("success")),
        );
        map_data.insert(
            Term::from(eetf::Atom::from("count")),
            Term::from(eetf::FixInteger::from(3)),
        );
        let map = eetf::Map::from(map_data);
        let tuple = eetf::Tuple::from(vec![Term::from(eetf::Atom::from("ok")), Term::from(map)]);

        let term = Term::from(tuple);
        let result = formatter.format_term(&term);

        // Check that it contains the expected elements (map order is not guaranteed)
        assert!(result.starts_with("#('ok #m("));
        assert!(result.contains("'status 'success"));
        assert!(result.contains("'count 3"));
        assert!(result.ends_with("))"));
    }
}
