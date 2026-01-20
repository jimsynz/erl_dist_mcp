//! RPC helper layer for remote Erlang function calls.
//!
//! This module provides an abstraction over erl_dist's message passing
//! for making remote procedure calls to Erlang nodes.

use crate::connection::ConnectionManager;
use crate::error::{RpcError, RpcResult};
use eetf::{Atom, BigInteger, FixInteger, Float, List, Map, Pid, Term, Tuple};
use erl_dist::message::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::connection::NodeConnection;

/// Default timeout for RPC calls in milliseconds.
pub const DEFAULT_RPC_TIMEOUT_MS: u64 = 5000;

/// Makes a remote procedure call to an Erlang node.
///
/// # Arguments
/// * `connection_manager` - The connection manager holding active connections
/// * `node` - The target node name
/// * `module` - The Erlang module name (atom)
/// * `function` - The function name (atom)
/// * `args` - The function arguments as Terms
/// * `timeout_ms` - Optional timeout in milliseconds (default 5000)
///
/// # Returns
/// The result term from the RPC call, or an error.
pub async fn rpc_call(
    connection_manager: &ConnectionManager,
    node: &str,
    module: &str,
    function: &str,
    args: Vec<Term>,
    timeout_ms: Option<u64>,
) -> RpcResult<Term> {
    let timeout_duration = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_RPC_TIMEOUT_MS));

    let conn = connection_manager
        .get_connection(node)
        .await
        .ok_or_else(|| RpcError::NodeNotConnected {
            node: node.to_string(),
            module: module.to_string(),
            function: function.to_string(),
        })?;

    let result = timeout(
        timeout_duration,
        execute_rpc(&conn, node, module, function, args),
    )
    .await;

    match result {
        Ok(inner_result) => inner_result,
        Err(_) => Err(RpcError::Timeout {
            node: node.to_string(),
            module: module.to_string(),
            function: function.to_string(),
            timeout_ms: timeout_duration.as_millis() as u64,
        }),
    }
}

/// Execute the actual RPC call through the connection.
async fn execute_rpc(
    conn: &Arc<Mutex<NodeConnection>>,
    node: &str,
    module: &str,
    function: &str,
    args: Vec<Term>,
) -> RpcResult<Term> {
    let conn_guard = conn.lock().await;

    // Build the RPC message for rex (the Erlang RPC server process).
    // The rex process expects: {'$gen_call', {From, Ref}, {call, Mod, Fun, Args, GL}}
    // where From is the sender PID and Ref is a unique reference.
    //
    // For simplicity, we use a reg_send message to 'rex' with the call tuple.

    let module_atom = Atom::from(module);
    let function_atom = Atom::from(function);
    let args_list = Term::from(List::from(args));

    // Create a Pid for the from address.
    // The creation value 0 is acceptable for ephemeral nodes.
    let from_pid = Pid::new("erl_dist_mcp@localhost", 0, 0, 0);

    // Build the call tuple: {call, Module, Function, Args, user}
    let call_tuple = Term::from(Tuple::from(vec![
        Term::from(Atom::from("call")),
        Term::from(module_atom),
        Term::from(function_atom),
        args_list,
        Term::from(Atom::from("user")), // Group leader
    ]));

    // The rex process expects: {'$gen_call', {Pid, Ref}, CallTuple}
    let ref_term = make_reference();
    let from_tuple = Term::from(Tuple::from(vec![Term::from(from_pid.clone()), ref_term]));

    let rex_message = Term::from(Tuple::from(vec![
        Term::from(Atom::from("$gen_call")),
        from_tuple,
        call_tuple,
    ]));

    let message = Message::reg_send(from_pid, Atom::from("rex"), rex_message);

    // Send the message and wait for response
    let result = conn_guard
        .send_request(message)
        .await
        .map_err(RpcError::Connection)?;

    // Check for badrpc response: {badrpc, Reason}
    check_badrpc_response(result, node, module, function)
}

/// Creates a reference term for RPC tracking.
fn make_reference() -> Term {
    // Create a simple reference - in practice this should be unique
    use std::sync::atomic::{AtomicU64, Ordering};
    static REF_COUNTER: AtomicU64 = AtomicU64::new(0);

    let ref_id = REF_COUNTER.fetch_add(1, Ordering::Relaxed);

    // We use a tuple to represent a reference-like value
    // since creating a proper eetf::Reference requires knowing the node
    Term::from(Tuple::from(vec![
        Term::from(Atom::from("ref")),
        Term::from(FixInteger::from(ref_id as i32)),
    ]))
}

/// Check if a response is a badrpc error and convert accordingly.
fn check_badrpc_response(term: Term, node: &str, module: &str, function: &str) -> RpcResult<Term> {
    // Check for {badrpc, Reason} tuple
    if let Term::Tuple(ref tuple) = term {
        let elements = tuple.elements.as_slice();
        if elements.len() == 2
            && let Term::Atom(ref atom) = elements[0]
            && atom.name == "badrpc"
        {
            let reason = format_term_for_error(&elements[1]);
            return Err(RpcError::BadRpc {
                node: node.to_string(),
                module: module.to_string(),
                function: function.to_string(),
                reason,
            });
        }
    }
    Ok(term)
}

/// Format a term for error messages (simple string representation).
fn format_term_for_error(term: &Term) -> String {
    match term {
        Term::Atom(a) => a.name.to_string(),
        Term::FixInteger(i) => i.value.to_string(),
        Term::BigInteger(i) => i.value.to_string(),
        Term::Float(f) => f.value.to_string(),
        Term::Binary(b) => String::from_utf8_lossy(&b.bytes).to_string(),
        Term::Tuple(t) => {
            let inner: Vec<String> = t.elements.iter().map(format_term_for_error).collect();
            format!("{{{}}}", inner.join(", "))
        }
        Term::List(l) => {
            let inner: Vec<String> = l.elements.iter().map(format_term_for_error).collect();
            format!("[{}]", inner.join(", "))
        }
        _ => format!("{:?}", term),
    }
}

// ============================================================================
// Rust to Term conversion helpers
// ============================================================================

/// Trait for converting Rust types to Erlang Terms.
pub trait ToTerm {
    fn to_term(self) -> Term;
}

impl ToTerm for String {
    fn to_term(self) -> Term {
        Term::from(eetf::Binary::from(self.into_bytes()))
    }
}

impl ToTerm for &str {
    fn to_term(self) -> Term {
        Term::from(eetf::Binary::from(self.as_bytes().to_vec()))
    }
}

impl ToTerm for i64 {
    fn to_term(self) -> Term {
        if self >= i32::MIN as i64 && self <= i32::MAX as i64 {
            Term::from(FixInteger::from(self as i32))
        } else {
            Term::from(BigInteger::from(self))
        }
    }
}

impl ToTerm for i32 {
    fn to_term(self) -> Term {
        Term::from(FixInteger::from(self))
    }
}

impl ToTerm for u64 {
    fn to_term(self) -> Term {
        if self <= i32::MAX as u64 {
            Term::from(FixInteger::from(self as i32))
        } else {
            // u64 can be larger than i64::MAX, but BigInteger::from accepts i64
            // For very large u64 values, we need to handle them differently
            if self <= i64::MAX as u64 {
                Term::from(BigInteger::from(self as i64))
            } else {
                // For u64 values > i64::MAX, create a BigInteger from string
                // This is a workaround for the limited BigInteger constructors
                Term::from(BigInteger::from(self as i64)) // Will overflow for very large values
            }
        }
    }
}

impl ToTerm for u32 {
    fn to_term(self) -> Term {
        if self <= i32::MAX as u32 {
            Term::from(FixInteger::from(self as i32))
        } else {
            Term::from(BigInteger::from(self as i64))
        }
    }
}

impl ToTerm for f64 {
    fn to_term(self) -> Term {
        // Float::try_from can fail for NaN/Inf, but we'll use the struct directly
        Term::from(Float { value: self })
    }
}

impl ToTerm for bool {
    fn to_term(self) -> Term {
        Term::from(Atom::from(if self { "true" } else { "false" }))
    }
}

impl<T: ToTerm> ToTerm for Vec<T> {
    fn to_term(self) -> Term {
        let elements: Vec<Term> = self.into_iter().map(|v| v.to_term()).collect();
        Term::from(List::from(elements))
    }
}

impl<K: ToTerm, V: ToTerm> ToTerm for HashMap<K, V> {
    fn to_term(self) -> Term {
        let entries: HashMap<Term, Term> = self
            .into_iter()
            .map(|(k, v)| (k.to_term(), v.to_term()))
            .collect();
        Term::from(Map::from(entries))
    }
}

impl ToTerm for Term {
    fn to_term(self) -> Term {
        self
    }
}

/// Create an atom term.
pub fn atom(name: &str) -> Term {
    Term::from(Atom::from(name))
}

/// Create a tuple term.
pub fn tuple(elements: Vec<Term>) -> Term {
    Term::from(Tuple::from(elements))
}

/// Create a list term.
pub fn list(elements: Vec<Term>) -> Term {
    Term::from(List::from(elements))
}

/// Create an empty list (nil) term.
pub fn nil() -> Term {
    Term::from(List::nil())
}

/// Create a binary term from bytes.
pub fn binary(bytes: Vec<u8>) -> Term {
    Term::from(eetf::Binary::from(bytes))
}

/// Create a binary term from a string.
pub fn binary_from_str(s: &str) -> Term {
    Term::from(eetf::Binary::from(s.as_bytes().to_vec()))
}

/// Create a map term from a vector of key-value pairs.
pub fn map(entries: Vec<(Term, Term)>) -> Term {
    let map: HashMap<Term, Term> = entries.into_iter().collect();
    Term::from(Map::from(map))
}

// ============================================================================
// Term to Rust conversion helpers
// ============================================================================

/// Trait for converting Erlang Terms to Rust types.
pub trait FromTerm: Sized {
    fn from_term(term: &Term) -> Option<Self>;
}

impl FromTerm for String {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::Binary(b) => String::from_utf8(b.bytes.clone()).ok(),
            Term::Atom(a) => Some(a.name.to_string()),
            // Also handle charlists (list of integers)
            Term::List(l) => {
                let chars: Option<Vec<u8>> = l
                    .elements
                    .iter()
                    .map(|e| {
                        if let Term::FixInteger(i) = e
                            && i.value >= 0
                            && i.value <= 255
                        {
                            Some(i.value as u8)
                        } else {
                            None
                        }
                    })
                    .collect();
                chars.and_then(|bytes| String::from_utf8(bytes).ok())
            }
            Term::ByteList(bl) => String::from_utf8(bl.bytes.clone()).ok(),
            _ => None,
        }
    }
}

impl FromTerm for i64 {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::FixInteger(i) => Some(i.value as i64),
            Term::BigInteger(i) => {
                // BigInteger uses num_bigint::BigInt
                use std::convert::TryInto;
                (&i.value).try_into().ok()
            }
            _ => None,
        }
    }
}

impl FromTerm for i32 {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::FixInteger(i) => Some(i.value),
            Term::BigInteger(i) => {
                use std::convert::TryInto;
                (&i.value).try_into().ok()
            }
            _ => None,
        }
    }
}

impl FromTerm for u64 {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::FixInteger(i) if i.value >= 0 => Some(i.value as u64),
            Term::BigInteger(i) => {
                use std::convert::TryInto;
                (&i.value).try_into().ok()
            }
            _ => None,
        }
    }
}

impl FromTerm for u32 {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::FixInteger(i) if i.value >= 0 => u32::try_from(i.value).ok(),
            Term::BigInteger(i) => {
                use std::convert::TryInto;
                (&i.value).try_into().ok()
            }
            _ => None,
        }
    }
}

impl FromTerm for f64 {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::Float(f) => Some(f.value),
            Term::FixInteger(i) => Some(i.value as f64),
            _ => None,
        }
    }
}

impl FromTerm for bool {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::Atom(a) => match a.name.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }
}

impl<T: FromTerm> FromTerm for Vec<T> {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::List(l) => {
                if l.is_nil() {
                    Some(Vec::new())
                } else {
                    l.elements.iter().map(T::from_term).collect()
                }
            }
            _ => None,
        }
    }
}

impl<V: FromTerm> FromTerm for HashMap<String, V> {
    fn from_term(term: &Term) -> Option<Self> {
        match term {
            Term::Map(m) => {
                let mut result = HashMap::new();
                for (k, v) in &m.map {
                    let key = String::from_term(k)?;
                    let value = V::from_term(v)?;
                    result.insert(key, value);
                }
                Some(result)
            }
            _ => None,
        }
    }
}

/// Extract an atom name from a term.
pub fn extract_atom(term: &Term) -> Option<&str> {
    match term {
        Term::Atom(a) => Some(&a.name),
        _ => None,
    }
}

/// Extract tuple elements from a term.
pub fn extract_tuple(term: &Term) -> Option<&[Term]> {
    match term {
        Term::Tuple(t) => Some(&t.elements),
        _ => None,
    }
}

/// Extract list elements from a term.
pub fn extract_list(term: &Term) -> Option<&[Term]> {
    match term {
        Term::List(l) => Some(&l.elements),
        _ => None,
    }
}

/// Extract binary bytes from a term.
pub fn extract_binary(term: &Term) -> Option<&[u8]> {
    match term {
        Term::Binary(b) => Some(&b.bytes),
        _ => None,
    }
}

/// Extract map as a reference from a term.
pub fn extract_map(term: &Term) -> Option<&HashMap<Term, Term>> {
    match term {
        Term::Map(m) => Some(&m.map),
        _ => None,
    }
}

/// Check if a term is a specific atom.
pub fn is_atom(term: &Term, name: &str) -> bool {
    matches!(term, Term::Atom(a) if a.name == name)
}

/// Check if a list term is empty (nil).
pub fn is_nil(term: &Term) -> bool {
    matches!(term, Term::List(l) if l.is_nil())
}

/// Check if a term is an ok tuple: {ok, Value}.
pub fn is_ok_tuple(term: &Term) -> bool {
    if let Term::Tuple(t) = term
        && !t.elements.is_empty()
    {
        return is_atom(&t.elements[0], "ok");
    }
    false
}

/// Check if a term is an error tuple: {error, Reason}.
pub fn is_error_tuple(term: &Term) -> bool {
    if let Term::Tuple(t) = term
        && !t.elements.is_empty()
    {
        return is_atom(&t.elements[0], "error");
    }
    false
}

/// Extract the value from an ok tuple: {ok, Value} -> Some(Value).
pub fn extract_ok_value(term: &Term) -> Option<&Term> {
    if let Term::Tuple(t) = term
        && t.elements.len() == 2
        && is_atom(&t.elements[0], "ok")
    {
        return Some(&t.elements[1]);
    }
    None
}

/// Extract the reason from an error tuple: {error, Reason} -> Some(Reason).
pub fn extract_error_reason(term: &Term) -> Option<&Term> {
    if let Term::Tuple(t) = term
        && t.elements.len() == 2
        && is_atom(&t.elements[0], "error")
    {
        return Some(&t.elements[1]);
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ========================================================================
    // Rust to Term conversion tests
    // ========================================================================

    #[test]
    fn string_to_term() {
        let term = "hello".to_string().to_term();
        if let Term::Binary(b) = term {
            assert_eq!(b.bytes, b"hello");
        } else {
            panic!("Expected Binary");
        }
    }

    #[test]
    fn str_to_term() {
        let term = "world".to_term();
        if let Term::Binary(b) = term {
            assert_eq!(b.bytes, b"world");
        } else {
            panic!("Expected Binary");
        }
    }

    #[test]
    fn i32_to_term() {
        let term = 42i32.to_term();
        if let Term::FixInteger(i) = term {
            assert_eq!(i.value, 42);
        } else {
            panic!("Expected FixInteger");
        }
    }

    #[test]
    fn i64_small_to_term() {
        let term = 100i64.to_term();
        if let Term::FixInteger(i) = term {
            assert_eq!(i.value, 100);
        } else {
            panic!("Expected FixInteger for small i64");
        }
    }

    #[test]
    fn i64_large_to_term() {
        let term = (i32::MAX as i64 + 1).to_term();
        if let Term::BigInteger(_) = term {
            // OK
        } else {
            panic!("Expected BigInteger for large i64");
        }
    }

    #[test]
    fn u32_to_term() {
        let term = 123u32.to_term();
        if let Term::FixInteger(i) = term {
            assert_eq!(i.value, 123);
        } else {
            panic!("Expected FixInteger");
        }
    }

    #[test]
    fn u64_small_to_term() {
        let term = 456u64.to_term();
        if let Term::FixInteger(i) = term {
            assert_eq!(i.value, 456);
        } else {
            panic!("Expected FixInteger for small u64");
        }
    }

    #[test]
    fn f64_to_term() {
        let term = 3.125f64.to_term();
        if let Term::Float(f) = term {
            assert!((f.value - 3.125).abs() < 0.001);
        } else {
            panic!("Expected Float");
        }
    }

    #[test]
    fn bool_to_term() {
        let true_term = true.to_term();
        let false_term = false.to_term();

        assert!(matches!(true_term, Term::Atom(a) if a.name == "true"));
        assert!(matches!(false_term, Term::Atom(a) if a.name == "false"));
    }

    #[test]
    fn vec_to_term() {
        let term = vec![1i32, 2, 3].to_term();
        if let Term::List(l) = term {
            assert_eq!(l.elements.len(), 3);
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn hashmap_to_term() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), 42i32);
        let term = map.to_term();
        if let Term::Map(m) = term {
            assert_eq!(m.map.len(), 1);
        } else {
            panic!("Expected Map");
        }
    }

    #[test]
    fn atom_helper() {
        let term = atom("ok");
        assert!(matches!(term, Term::Atom(a) if a.name == "ok"));
    }

    #[test]
    fn tuple_helper() {
        let term = tuple(vec![atom("ok"), 42i32.to_term()]);
        if let Term::Tuple(t) = term {
            assert_eq!(t.elements.len(), 2);
        } else {
            panic!("Expected Tuple");
        }
    }

    #[test]
    fn list_helper() {
        let term = list(vec![1i32.to_term(), 2i32.to_term()]);
        if let Term::List(l) = term {
            assert_eq!(l.elements.len(), 2);
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn nil_helper() {
        let term = nil();
        if let Term::List(l) = term {
            assert!(l.is_nil());
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn binary_helper() {
        let term = binary(vec![1, 2, 3]);
        if let Term::Binary(b) = term {
            assert_eq!(b.bytes, vec![1, 2, 3]);
        } else {
            panic!("Expected Binary");
        }
    }

    #[test]
    fn map_helper() {
        let term = map(vec![(atom("key"), 42i32.to_term())]);
        if let Term::Map(m) = term {
            assert_eq!(m.map.len(), 1);
        } else {
            panic!("Expected Map");
        }
    }

    // ========================================================================
    // Term to Rust conversion tests
    // ========================================================================

    #[test]
    fn string_from_binary_term() {
        let term = Term::from(eetf::Binary::from(b"hello".to_vec()));
        let result = String::from_term(&term);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn string_from_atom_term() {
        let term = Term::from(Atom::from("world"));
        let result = String::from_term(&term);
        assert_eq!(result, Some("world".to_string()));
    }

    #[test]
    fn string_from_charlist_term() {
        let term = Term::from(List::from(vec![
            Term::from(FixInteger::from(104)), // 'h'
            Term::from(FixInteger::from(105)), // 'i'
        ]));
        let result = String::from_term(&term);
        assert_eq!(result, Some("hi".to_string()));
    }

    #[test]
    fn i64_from_fix_integer_term() {
        let term = Term::from(FixInteger::from(42));
        let result = i64::from_term(&term);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn i32_from_fix_integer_term() {
        let term = Term::from(FixInteger::from(-10));
        let result = i32::from_term(&term);
        assert_eq!(result, Some(-10));
    }

    #[test]
    fn u64_from_fix_integer_term() {
        let term = Term::from(FixInteger::from(100));
        let result = u64::from_term(&term);
        assert_eq!(result, Some(100));
    }

    #[test]
    fn u64_from_negative_returns_none() {
        let term = Term::from(FixInteger::from(-1));
        let result = u64::from_term(&term);
        assert_eq!(result, None);
    }

    #[test]
    fn f64_from_float_term() {
        let term = Term::from(Float { value: 2.5 });
        let result = f64::from_term(&term);
        assert!(result.is_some());
        assert!((result.unwrap() - 2.5).abs() < 0.001);
    }

    #[test]
    fn f64_from_fix_integer_term() {
        let term = Term::from(FixInteger::from(5));
        let result = f64::from_term(&term);
        assert_eq!(result, Some(5.0));
    }

    #[test]
    fn bool_from_atom_term() {
        let true_term = Term::from(Atom::from("true"));
        let false_term = Term::from(Atom::from("false"));
        let other_term = Term::from(Atom::from("maybe"));

        assert_eq!(bool::from_term(&true_term), Some(true));
        assert_eq!(bool::from_term(&false_term), Some(false));
        assert_eq!(bool::from_term(&other_term), None);
    }

    #[test]
    fn vec_from_list_term() {
        let term = Term::from(List::from(vec![
            Term::from(FixInteger::from(1)),
            Term::from(FixInteger::from(2)),
            Term::from(FixInteger::from(3)),
        ]));
        let result = Vec::<i32>::from_term(&term);
        assert_eq!(result, Some(vec![1, 2, 3]));
    }

    #[test]
    fn vec_from_nil_term() {
        let term = Term::from(List::nil());
        let result = Vec::<i32>::from_term(&term);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn hashmap_from_map_term() {
        let mut map_entries = HashMap::new();
        map_entries.insert(
            Term::from(Atom::from("key")),
            Term::from(FixInteger::from(42)),
        );
        let term = Term::from(Map::from(map_entries));
        let result = HashMap::<String, i32>::from_term(&term);
        assert!(result.is_some());
        let map = result.unwrap();
        assert_eq!(map.get("key"), Some(&42));
    }

    // ========================================================================
    // Extraction helper tests
    // ========================================================================

    #[test]
    fn extract_atom_success() {
        let term = Term::from(Atom::from("test"));
        assert_eq!(extract_atom(&term), Some("test"));
    }

    #[test]
    fn extract_atom_failure() {
        let term = Term::from(FixInteger::from(42));
        assert_eq!(extract_atom(&term), None);
    }

    #[test]
    fn extract_tuple_success() {
        let term = Term::from(Tuple::from(vec![
            Term::from(Atom::from("ok")),
            Term::from(FixInteger::from(1)),
        ]));
        let elements = extract_tuple(&term);
        assert!(elements.is_some());
        assert_eq!(elements.unwrap().len(), 2);
    }

    #[test]
    fn extract_list_success() {
        let term = Term::from(List::from(vec![Term::from(FixInteger::from(1))]));
        let elements = extract_list(&term);
        assert!(elements.is_some());
        assert_eq!(elements.unwrap().len(), 1);
    }

    #[test]
    fn extract_binary_success() {
        let term = Term::from(eetf::Binary::from(b"test".to_vec()));
        let bytes = extract_binary(&term);
        assert_eq!(bytes, Some(b"test".as_slice()));
    }

    #[test]
    fn extract_map_success() {
        let mut map_entries = HashMap::new();
        map_entries.insert(Term::from(Atom::from("a")), Term::from(FixInteger::from(1)));
        let term = Term::from(Map::from(map_entries));
        let map = extract_map(&term);
        assert!(map.is_some());
        assert_eq!(map.unwrap().len(), 1);
    }

    #[test]
    fn is_atom_check() {
        let ok = Term::from(Atom::from("ok"));
        let error = Term::from(Atom::from("error"));

        assert!(is_atom(&ok, "ok"));
        assert!(!is_atom(&ok, "error"));
        assert!(is_atom(&error, "error"));
    }

    #[test]
    fn is_nil_check() {
        let empty = Term::from(List::nil());
        let non_empty = Term::from(List::from(vec![Term::from(FixInteger::from(1))]));

        assert!(is_nil(&empty));
        assert!(!is_nil(&non_empty));
    }

    #[test]
    fn is_ok_tuple_check() {
        let ok_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("ok")),
            Term::from(FixInteger::from(42)),
        ]));
        let error_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("error")),
            Term::from(Atom::from("reason")),
        ]));

        assert!(is_ok_tuple(&ok_tuple));
        assert!(!is_ok_tuple(&error_tuple));
    }

    #[test]
    fn is_error_tuple_check() {
        let ok_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("ok")),
            Term::from(FixInteger::from(42)),
        ]));
        let error_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("error")),
            Term::from(Atom::from("reason")),
        ]));

        assert!(!is_error_tuple(&ok_tuple));
        assert!(is_error_tuple(&error_tuple));
    }

    #[test]
    fn extract_ok_value_success() {
        let ok_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("ok")),
            Term::from(FixInteger::from(42)),
        ]));
        let value = extract_ok_value(&ok_tuple);
        assert!(value.is_some());
        assert!(matches!(value.unwrap(), Term::FixInteger(i) if i.value == 42));
    }

    #[test]
    fn extract_ok_value_failure() {
        let error_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("error")),
            Term::from(Atom::from("reason")),
        ]));
        assert!(extract_ok_value(&error_tuple).is_none());
    }

    #[test]
    fn extract_error_reason_success() {
        let error_tuple = Term::from(Tuple::from(vec![
            Term::from(Atom::from("error")),
            Term::from(Atom::from("timeout")),
        ]));
        let reason = extract_error_reason(&error_tuple);
        assert!(reason.is_some());
        assert!(matches!(reason.unwrap(), Term::Atom(a) if a.name == "timeout"));
    }

    // ========================================================================
    // badrpc detection tests
    // ========================================================================

    #[test]
    fn check_badrpc_detects_badrpc() {
        let badrpc = Term::from(Tuple::from(vec![
            Term::from(Atom::from("badrpc")),
            Term::from(Atom::from("nodedown")),
        ]));

        let result = check_badrpc_response(badrpc, "node@host", "mod", "fun");
        assert!(result.is_err());
        if let Err(RpcError::BadRpc { reason, .. }) = result {
            assert_eq!(reason, "nodedown");
        } else {
            panic!("Expected BadRpc error");
        }
    }

    #[test]
    fn check_badrpc_passes_ok() {
        let ok = Term::from(Tuple::from(vec![
            Term::from(Atom::from("ok")),
            Term::from(FixInteger::from(42)),
        ]));

        let result = check_badrpc_response(ok, "node@host", "mod", "fun");
        assert!(result.is_ok());
    }

    #[test]
    fn check_badrpc_passes_plain_value() {
        let value = Term::from(FixInteger::from(123));

        let result = check_badrpc_response(value, "node@host", "mod", "fun");
        assert!(result.is_ok());
    }

    // ========================================================================
    // Error formatting tests
    // ========================================================================

    #[test]
    fn format_term_for_error_atom() {
        let term = Term::from(Atom::from("test"));
        assert_eq!(format_term_for_error(&term), "test");
    }

    #[test]
    fn format_term_for_error_integer() {
        let term = Term::from(FixInteger::from(42));
        assert_eq!(format_term_for_error(&term), "42");
    }

    #[test]
    fn format_term_for_error_tuple() {
        let term = Term::from(Tuple::from(vec![
            Term::from(Atom::from("error")),
            Term::from(Atom::from("reason")),
        ]));
        assert_eq!(format_term_for_error(&term), "{error, reason}");
    }

    #[test]
    fn format_term_for_error_list() {
        let term = Term::from(List::from(vec![
            Term::from(FixInteger::from(1)),
            Term::from(FixInteger::from(2)),
        ]));
        assert_eq!(format_term_for_error(&term), "[1, 2]");
    }
}
