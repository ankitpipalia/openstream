//! Bounded, secret-free diagnostics for operator support and release checks.
//!
//! This crate deliberately does not read files, environment variables, logs, or
//! settings. Callers provide individual observations, and this crate redacts
//! them before storing them in a bundle. Pairing material and clipboard text
//! have class-specific APIs that never retain the supplied value.

use serde::Serialize;
use serde_json::{Map, Value};
use std::fmt::{self, Write as _};

pub const DIAGNOSTIC_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MAX_RECORDS: usize = 256;
pub const DEFAULT_MAX_VALUE_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_JSON_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_LABEL_BYTES: usize = 128;
const MAX_REDACTION_INPUT_BYTES: usize = 1024 * 1024;
const OVERSIZED_MARKER: &str = "[REDACTED:oversized]";
const TRUNCATION_SUFFIX: &str = "...";

/// A category whose input must not be retained verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    Token,
    Key,
    PairingJson,
    Clipboard,
    UserPath,
}

impl RedactionClass {
    const fn marker(self) -> &'static str {
        match self {
            Self::Token => "[REDACTED:token]",
            Self::Key => "[REDACTED:key]",
            Self::PairingJson => "[REDACTED:pairing]",
            Self::Clipboard => "[REDACTED:clipboard]",
            Self::UserPath => "[REDACTED:user-path]",
        }
    }
}

/// Output formats supported by [`DiagnosticBundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Text,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Json => "JSON",
            Self::Text => "text",
        })
    }
}

/// Errors returned without embedding caller-supplied values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticError {
    InvalidPolicy,
    InvalidReleaseManifest,
    RecordLimitExceeded,
    ExportTooLarge {
        format: ExportFormat,
        limit: usize,
        actual: usize,
    },
    Serialization,
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("diagnostic policy limits are invalid"),
            Self::InvalidReleaseManifest => {
                formatter.write_str("release manifest contains an invalid field")
            }
            Self::RecordLimitExceeded => formatter.write_str("diagnostic record limit exceeded"),
            Self::ExportTooLarge {
                format,
                limit,
                actual,
            } => write!(
                formatter,
                "{format} diagnostic export is {actual} bytes; limit is {limit} bytes"
            ),
            Self::Serialization => formatter.write_str("diagnostic export serialization failed"),
        }
    }
}

impl std::error::Error for DiagnosticError {}

/// Limits and deterministic redaction rules for a support bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RedactionPolicy {
    max_value_bytes: usize,
    max_json_bytes: usize,
    max_text_bytes: usize,
    max_records: usize,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_json_bytes: DEFAULT_MAX_JSON_BYTES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
        }
    }
}

impl RedactionPolicy {
    /// Create a policy with bounded values, exports, and record count.
    pub fn new(
        max_value_bytes: usize,
        max_json_bytes: usize,
        max_text_bytes: usize,
        max_records: usize,
    ) -> Result<Self, DiagnosticError> {
        if !(1..=MAX_POLICY_BYTES).contains(&max_value_bytes)
            || !(1..=MAX_POLICY_BYTES).contains(&max_json_bytes)
            || !(1..=MAX_POLICY_BYTES).contains(&max_text_bytes)
            || !(1..=DEFAULT_MAX_RECORDS * 16).contains(&max_records)
        {
            return Err(DiagnosticError::InvalidPolicy);
        }
        Ok(Self {
            max_value_bytes,
            max_json_bytes,
            max_text_bytes,
            max_records,
        })
    }

    pub const fn max_value_bytes(self) -> usize {
        self.max_value_bytes
    }

    pub const fn max_json_bytes(self) -> usize {
        self.max_json_bytes
    }

    pub const fn max_text_bytes(self) -> usize {
        self.max_text_bytes
    }

    pub const fn max_records(self) -> usize {
        self.max_records
    }

    /// Redact sensitive fields and user paths from a bounded diagnostic line.
    pub fn redact_text(&self, input: &str) -> String {
        if input.len()
            > self
                .max_value_bytes
                .saturating_mul(64)
                .min(MAX_REDACTION_INPUT_BYTES)
        {
            return truncate_utf8(OVERSIZED_MARKER, self.max_value_bytes);
        }

        let output = if looks_like_json(input) {
            match serde_json::from_str::<Value>(input) {
                Ok(value) => serde_json::to_string(&self.redact_json_value(value))
                    .unwrap_or_else(|_| OVERSIZED_MARKER.to_string()),
                Err(_) => self.redact_plain_text(input),
            }
        } else {
            self.redact_plain_text(input)
        };
        truncate_utf8(&output, self.max_value_bytes)
    }

    /// Replace a value whose category is already known by the caller.
    pub fn redact_class(&self, class: RedactionClass, _input: &str) -> String {
        truncate_utf8(class.marker(), self.max_value_bytes)
    }

    /// Redact a JSON settings/pairing snapshot without retaining its raw input.
    pub fn redact_json(&self, input: &str) -> String {
        if input.len()
            > self
                .max_value_bytes
                .saturating_mul(64)
                .min(MAX_REDACTION_INPUT_BYTES)
        {
            return truncate_utf8(OVERSIZED_MARKER, self.max_value_bytes);
        }
        match serde_json::from_str::<Value>(input) {
            Ok(value) => {
                let sanitized = serde_json::to_string(&self.redact_json_value(value))
                    .unwrap_or_else(|_| OVERSIZED_MARKER.to_string());
                truncate_utf8(&sanitized, self.max_value_bytes)
            }
            Err(_) => self.redact_text(input),
        }
    }

    fn redact_json_value(&self, value: Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut sanitized = Map::with_capacity(object.len());
                for (key, value) in object {
                    let value = match field_redaction_class(&key) {
                        Some(RedactionClass::PairingJson)
                            if value.is_object() || value.is_array() =>
                        {
                            self.redact_json_value(value)
                        }
                        Some(class) => Value::String(self.redact_class(class, &value.to_string())),
                        None => self.redact_json_value(value),
                    };
                    sanitized.insert(key, value);
                }
                Value::Object(sanitized)
            }
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|value| self.redact_json_value(value))
                    .collect(),
            ),
            Value::String(text) => Value::String(self.redact_plain_text(&text)),
            other => other,
        }
    }

    fn redact_plain_text(&self, input: &str) -> String {
        let with_pem = redact_pem_blocks(input);
        let with_bearer = redact_bearer(&with_pem);
        let with_fields = redact_sensitive_fields(&with_bearer);
        redact_user_paths(&with_fields)
    }
}

/// A release/build identity containing only non-secret metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseManifest {
    product: String,
    version: String,
    git_revision: String,
    target: String,
    profile: ReleaseProfile,
}

impl ReleaseManifest {
    pub fn new(
        product: impl Into<String>,
        version: impl Into<String>,
        git_revision: impl Into<String>,
        target: impl Into<String>,
        profile: ReleaseProfile,
    ) -> Result<Self, DiagnosticError> {
        let product = bounded_identifier(product.into(), 64)?;
        let version = bounded_identifier(version.into(), 64)?;
        let git_revision = bounded_identifier(git_revision.into(), 128)?;
        let target = bounded_identifier(target.into(), 128)?;
        Ok(Self {
            product,
            version,
            git_revision,
            target,
            profile,
        })
    }

    pub fn product(&self) -> &str {
        &self.product
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn git_revision(&self) -> &str {
        &self.git_revision
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub const fn profile(&self) -> ReleaseProfile {
        self.profile
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseProfile {
    Debug,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DiagnosticRecord {
    Log {
        source: String,
        message: String,
    },
    Setting {
        name: String,
        value: String,
    },
    Status {
        component: String,
        state: String,
    },
    Value {
        label: String,
        class: RedactionClass,
        value: String,
    },
    ClipboardObservation {
        present: bool,
        byte_len: u64,
    },
}

#[derive(Debug, Serialize)]
struct DiagnosticExport<'a> {
    schema_version: u32,
    release: &'a ReleaseManifest,
    records: &'a [DiagnosticRecord],
}

/// A bounded diagnostic bundle. It stores only redacted records and release
/// metadata; it never reads or embeds raw settings, logs, pairing files, or
/// clipboard contents.
#[derive(Debug, Clone)]
pub struct DiagnosticBundle {
    release: ReleaseManifest,
    policy: RedactionPolicy,
    records: Vec<DiagnosticRecord>,
}

impl DiagnosticBundle {
    pub fn new(release: ReleaseManifest, policy: RedactionPolicy) -> Self {
        Self {
            release,
            policy,
            records: Vec::new(),
        }
    }

    pub fn release(&self) -> &ReleaseManifest {
        &self.release
    }

    pub const fn policy(&self) -> RedactionPolicy {
        self.policy
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Add one already-redacted diagnostic log line.
    pub fn add_log(
        &mut self,
        source: impl AsRef<str>,
        message: impl AsRef<str>,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::Log {
            source: self.policy.redact_text(source.as_ref()),
            message: self.policy.redact_text(message.as_ref()),
        })
    }

    /// Add a setting observation after field-aware redaction. This is not a
    /// settings-file import and cannot retain pairing or secret values.
    pub fn add_setting(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::Setting {
            name: bounded_label(&self.policy, name.as_ref()),
            value: self.policy.redact_text(value.as_ref()),
        })
    }

    /// Add a JSON settings/pairing snapshot only after recursive redaction.
    pub fn add_settings_snapshot(
        &mut self,
        name: impl AsRef<str>,
        json: impl AsRef<str>,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::Setting {
            name: bounded_label(&self.policy, name.as_ref()),
            value: self.policy.redact_json(json.as_ref()),
        })
    }

    pub fn add_status(
        &mut self,
        component: impl AsRef<str>,
        state: impl AsRef<str>,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::Status {
            component: bounded_label(&self.policy, component.as_ref()),
            state: self.policy.redact_text(state.as_ref()),
        })
    }

    /// Add a presence/size observation without accepting clipboard text.
    pub fn add_clipboard_observation(
        &mut self,
        present: bool,
        byte_len: usize,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::ClipboardObservation {
            present,
            byte_len: u64::try_from(byte_len).unwrap_or(u64::MAX),
        })
    }

    /// Add a value using an explicit redaction class. The input is discarded.
    pub fn add_redacted_value(
        &mut self,
        label: impl AsRef<str>,
        class: RedactionClass,
        value: impl AsRef<str>,
    ) -> Result<(), DiagnosticError> {
        self.push(DiagnosticRecord::Value {
            label: bounded_label(&self.policy, label.as_ref()),
            class,
            value: self.policy.redact_class(class, value.as_ref()),
        })
    }

    /// Export valid, bounded JSON. Oversized output is rejected rather than
    /// truncated into invalid JSON.
    pub fn export_json(&self) -> Result<String, DiagnosticError> {
        let export = DiagnosticExport {
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
            release: &self.release,
            records: &self.records,
        };
        let bytes = serde_json::to_vec(&export).map_err(|_| DiagnosticError::Serialization)?;
        if bytes.len() > self.policy.max_json_bytes {
            return Err(DiagnosticError::ExportTooLarge {
                format: ExportFormat::Json,
                limit: self.policy.max_json_bytes,
                actual: bytes.len(),
            });
        }
        String::from_utf8(bytes).map_err(|_| DiagnosticError::Serialization)
    }

    /// Export bounded human-readable text without copying raw source files.
    pub fn export_text(&self) -> Result<String, DiagnosticError> {
        let mut text = String::new();
        writeln!(
            text,
            "OpenStream diagnostics schema={DIAGNOSTIC_SCHEMA_VERSION}"
        )
        .unwrap();
        writeln!(text, "release.product={}", self.release.product).unwrap();
        writeln!(text, "release.version={}", self.release.version).unwrap();
        writeln!(text, "release.revision={}", self.release.git_revision).unwrap();
        writeln!(text, "release.target={}", self.release.target).unwrap();
        writeln!(text, "release.profile={:?}", self.release.profile).unwrap();
        for record in &self.records {
            match record {
                DiagnosticRecord::Log { source, message } => {
                    writeln!(text, "log[{source}]={message}").unwrap();
                }
                DiagnosticRecord::Setting { name, value } => {
                    writeln!(text, "setting[{name}]={value}").unwrap();
                }
                DiagnosticRecord::Status { component, state } => {
                    writeln!(text, "status[{component}]={state}").unwrap();
                }
                DiagnosticRecord::Value {
                    label,
                    class,
                    value,
                } => {
                    writeln!(text, "value[{label}][{class:?}]={value}").unwrap();
                }
                DiagnosticRecord::ClipboardObservation { present, byte_len } => {
                    writeln!(text, "clipboard.present={present}").unwrap();
                    writeln!(text, "clipboard.byte_len={byte_len}").unwrap();
                }
            }
        }
        if text.len() > self.policy.max_text_bytes {
            return Err(DiagnosticError::ExportTooLarge {
                format: ExportFormat::Text,
                limit: self.policy.max_text_bytes,
                actual: text.len(),
            });
        }
        Ok(text)
    }

    fn push(&mut self, record: DiagnosticRecord) -> Result<(), DiagnosticError> {
        if self.records.len() >= self.policy.max_records {
            return Err(DiagnosticError::RecordLimitExceeded);
        }
        self.records.push(record);
        Ok(())
    }
}

fn bounded_identifier(value: String, max_bytes: usize) -> Result<String, DiagnosticError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(DiagnosticError::InvalidReleaseManifest);
    }
    Ok(value)
}

fn bounded_label(policy: &RedactionPolicy, value: &str) -> String {
    truncate_utf8(&policy.redact_text(value), MAX_LABEL_BYTES)
}

fn looks_like_json(input: &str) -> bool {
    matches!(
        input.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    )
}

fn field_redaction_class(field: &str) -> Option<RedactionClass> {
    let normalized = field.to_ascii_lowercase();
    let field = normalized.as_str();
    if field.contains("clipboard") {
        Some(RedactionClass::Clipboard)
    } else if field.contains("pairing") {
        Some(RedactionClass::PairingJson)
    } else if field.contains("private")
        || field.contains("signing") && field.contains("key")
        || field.contains("identity") && field.contains("key") && !field.contains("public")
        || field.contains("secret") && field.contains("key")
    {
        Some(RedactionClass::Key)
    } else if field.contains("token")
        || field.contains("secret")
        || field.contains("password")
        || field.contains("credential")
        || field.contains("authorization")
        || field.contains("bearer")
        || field.contains("relay_ticket")
        || field.contains("turn_secret")
    {
        Some(RedactionClass::Token)
    } else if field == "path"
        || field.ends_with("_path")
        || field == "cwd"
        || field == "home"
        || field == "user_home"
    {
        Some(RedactionClass::UserPath)
    } else {
        None
    }
}

fn redact_pem_blocks(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative_start) = input[cursor..].find("-----BEGIN") {
        let start = cursor + relative_start;
        output.push_str(&input[cursor..start]);
        let begin_marker_len = "-----BEGIN".len();
        let Some(header_end_relative) = input[start + begin_marker_len..].find("-----") else {
            output.push_str(&input[start..]);
            return output;
        };
        let header_end = start + begin_marker_len + header_end_relative + 5;
        let header = &input[start..header_end];
        if !header.to_ascii_uppercase().contains("PRIVATE KEY")
            && !header.to_ascii_uppercase().contains("SECRET KEY")
        {
            output.push_str(&input[start..header_end]);
            cursor = header_end;
            continue;
        }
        let Some(end_relative) = input[header_end..].find("-----END") else {
            output.push_str(RedactionClass::Key.marker());
            return output;
        };
        let end_start = header_end + end_relative;
        let Some(end_suffix_relative) = input[end_start..].find("-----") else {
            output.push_str(RedactionClass::Key.marker());
            return output;
        };
        let end = end_start + end_suffix_relative + 5;
        output.push_str(RedactionClass::Key.marker());
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn redact_bearer(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find("bearer") {
        let start = cursor + relative;
        let end_word = start + "bearer".len();
        if !is_identifier_boundary(&lower, start, end_word)
            || !lower
                .as_bytes()
                .get(end_word)
                .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            output.push_str(&input[cursor..end_word]);
            cursor = end_word;
            continue;
        }
        let value_start = skip_whitespace(input, end_word);
        let value_end = consume_value(input, value_start);
        output.push_str(&input[cursor..value_start]);
        output.push_str(RedactionClass::Token.marker());
        cursor = value_end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn redact_sensitive_fields(input: &str) -> String {
    const FIELDS: &[(&str, RedactionClass)] = &[
        ("pairing_json", RedactionClass::PairingJson),
        ("pairing", RedactionClass::PairingJson),
        ("identity_private_key", RedactionClass::Key),
        ("private_key", RedactionClass::Key),
        ("private", RedactionClass::Key),
        ("secret_key", RedactionClass::Key),
        ("encryption_key", RedactionClass::Key),
        ("signing_key", RedactionClass::Key),
        ("x25519_private", RedactionClass::Key),
        ("ed25519_private", RedactionClass::Key),
        ("host_token", RedactionClass::Token),
        ("client_token", RedactionClass::Token),
        ("guest_token", RedactionClass::Token),
        ("session_token", RedactionClass::Token),
        ("access_token", RedactionClass::Token),
        ("api_key", RedactionClass::Token),
        ("host_secret", RedactionClass::Token),
        ("client_secret", RedactionClass::Token),
        ("relay_secret", RedactionClass::Token),
        ("relay_ticket", RedactionClass::Token),
        ("turn_secret", RedactionClass::Token),
        ("turn_password", RedactionClass::Token),
        ("relay_password", RedactionClass::Token),
        ("authorization", RedactionClass::Token),
        ("password", RedactionClass::Token),
        ("credential", RedactionClass::Token),
        ("token", RedactionClass::Token),
        ("clipboard_text", RedactionClass::Clipboard),
        ("clipboard", RedactionClass::Clipboard),
        ("file_path", RedactionClass::UserPath),
        ("user_path", RedactionClass::UserPath),
    ];
    let mut output = input.to_string();
    for &(field, class) in FIELDS {
        output = redact_field(&output, field, class);
    }
    output
}

fn redact_field(input: &str, field: &str, class: RedactionClass) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find(field) {
        let start = cursor + relative;
        let end_field = start + field.len();
        if !is_identifier_boundary(&lower, start, end_field) {
            output.push_str(&input[cursor..end_field]);
            cursor = end_field;
            continue;
        }
        let mut delimiter_start = skip_whitespace(input, end_field);
        if input.as_bytes().get(delimiter_start) == Some(&b'"') {
            delimiter_start = skip_whitespace(input, delimiter_start + 1);
        }
        let Some(delimiter) = input.as_bytes().get(delimiter_start) else {
            output.push_str(&input[cursor..]);
            cursor = input.len();
            break;
        };
        if *delimiter != b'=' && *delimiter != b':' {
            output.push_str(&input[cursor..end_field]);
            cursor = end_field;
            continue;
        }
        let value_start = skip_whitespace(input, delimiter_start + 1);
        let value_end = if class == RedactionClass::PairingJson {
            consume_json_value(input, value_start)
        } else {
            consume_value(input, value_start)
        };
        output.push_str(&input[cursor..value_start]);
        output.push_str(class.marker());
        cursor = value_end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn redact_user_paths(input: &str) -> String {
    const PREFIXES: &[&str] = &["/Users/", "/home/", "C:\\Users\\", "D:\\Users\\"];
    let mut output = input.to_string();
    for prefix in PREFIXES {
        output = redact_path_prefix(&output, prefix);
    }
    output
}

fn redact_path_prefix(input: &str, prefix: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let prefix_lower = prefix.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find(&prefix_lower) {
        let start = cursor + relative;
        let end = consume_path(input, start);
        output.push_str(&input[cursor..start]);
        output.push_str(RedactionClass::UserPath.marker());
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn consume_path(input: &str, start: usize) -> usize {
    input[start..]
        .char_indices()
        .find_map(|(offset, character)| {
            (offset > 0
                && (character.is_whitespace()
                    || matches!(character, '"' | '\'' | ',' | ';' | ']' | '}')))
            .then_some(start + offset)
        })
        .unwrap_or(input.len())
}

fn is_identifier_boundary(input: &str, start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|index| input.as_bytes().get(index));
    let after = input.as_bytes().get(end);
    before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        && after.is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn skip_whitespace(input: &str, mut index: usize) -> usize {
    while input
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn consume_value(input: &str, start: usize) -> usize {
    if input.as_bytes().get(start) == Some(&b'"') {
        let mut escaped = false;
        for (offset, character) in input[start + 1..].char_indices() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return start + 1 + offset + character.len_utf8();
            }
        }
        return input.len();
    }
    input[start..]
        .char_indices()
        .find_map(|(offset, character)| {
            (offset > 0
                && (character.is_whitespace() || matches!(character, ',' | ';' | ']' | '}')))
            .then_some(start + offset)
        })
        .unwrap_or(input.len())
}

fn consume_json_value(input: &str, start: usize) -> usize {
    let Some(&opening) = input.as_bytes().get(start) else {
        return input.len();
    };
    let closing = match opening {
        b'{' => b'}',
        b'[' => b']',
        b'"' => return consume_value(input, start),
        _ => return consume_value(input, start),
    };
    let mut depth = 0_u32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, character) in input[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
        } else if character == opening as char {
            depth = depth.saturating_add(1);
        } else if character == closing as char {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return start + offset + character.len_utf8();
            }
        }
    }
    input.len()
}

fn truncate_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    if max_bytes <= TRUNCATION_SUFFIX.len() {
        return input
            .char_indices()
            .take_while(|(offset, character)| *offset + character.len_utf8() <= max_bytes)
            .map(|(_, character)| character)
            .collect();
    }
    let target = max_bytes - TRUNCATION_SUFFIX.len();
    let end = input
        .char_indices()
        .take_while(|(offset, character)| *offset + character.len_utf8() <= target)
        .map(|(offset, character)| offset + character.len_utf8())
        .last()
        .unwrap_or(0);
    let mut output = input[..end].to_string();
    output.push_str(TRUNCATION_SUFFIX);
    output
}

#[cfg(test)]
mod tests {
    use super::{
        DiagnosticBundle, DiagnosticError, RedactionClass, RedactionPolicy, ReleaseManifest,
        ReleaseProfile,
    };

    fn manifest() -> ReleaseManifest {
        ReleaseManifest::new(
            "openstream",
            "0.1.0",
            "0123456789abcdef0123456789abcdef01234567",
            "aarch64-apple-darwin",
            ReleaseProfile::Release,
        )
        .expect("test manifest is valid")
    }

    #[test]
    fn redacts_bearer_and_named_token_values() {
        let policy = RedactionPolicy::default();
        let output = policy.redact_text(
            "Authorization: Bearer bearer-secret; host_token=host-secret client_token: client-secret",
        );

        assert!(!output.contains("bearer-secret"));
        assert!(!output.contains("host-secret"));
        assert!(!output.contains("client-secret"));
        assert!(output.contains("[REDACTED:token]"));
    }

    #[test]
    fn redacts_quoted_secret_fields_in_embedded_log_json() {
        let policy = RedactionPolicy::default();
        let output = policy.redact_text(
            r#"received invalid payload: {"host_token":"quoted-token-secret","private_key":"quoted-key-secret"}"#,
        );

        assert!(!output.contains("quoted-token-secret"));
        assert!(!output.contains("quoted-key-secret"));
        assert!(output.contains("[REDACTED:token]"));
        assert!(output.contains("[REDACTED:key]"));
    }

    #[test]
    fn redacts_pairing_json_embedded_in_a_log_assignment() {
        let policy = RedactionPolicy::default();
        let output = policy
            .redact_text(r#"pairing={"session_id":"session-2", "host_token":"embedded-secret"}"#);

        assert!(!output.contains("embedded-secret"));
        assert!(!output.contains("session-2"));
        assert!(output.contains("[REDACTED:pairing]"));
    }

    #[test]
    fn redacts_private_and_identity_key_values() {
        let policy = RedactionPolicy::default();
        let output = policy.redact_text(
            "identity_private_key=ed25519-private-secret public_key=public-is-not-secret\n-----BEGIN PRIVATE KEY-----\nkey-material-secret\n-----END PRIVATE KEY-----",
        );

        assert!(!output.contains("ed25519-private-secret"));
        assert!(!output.contains("key-material-secret"));
        assert!(output.contains("public-is-not-secret"));
        assert!(output.contains("[REDACTED:key]"));
    }

    #[test]
    fn pairing_json_is_redacted_before_bundle_export() {
        let mut bundle = DiagnosticBundle::new(manifest(), RedactionPolicy::default());
        bundle
            .add_settings_snapshot(
                "pairing",
                r#"{"session_id":"session-1","host_token":"host-secret","client_token":"client-secret","identity_private_key":"private-secret"}"#,
            )
            .expect("pairing snapshot is bounded");

        let json = bundle.export_json().expect("diagnostic JSON is valid");
        assert!(!json.contains("host-secret"));
        assert!(!json.contains("client-secret"));
        assert!(!json.contains("private-secret"));
        assert!(json.contains("session-1"));
        assert!(json.contains("[REDACTED:token]"));
        assert!(json.contains("[REDACTED:key]"));
    }

    #[test]
    fn clipboard_content_is_never_stored() {
        let policy = RedactionPolicy::default();
        let output = policy.redact_class(
            RedactionClass::Clipboard,
            "copy this private clipboard text",
        );

        assert_eq!(output, "[REDACTED:clipboard]");
        assert!(!output.contains("copy this private clipboard text"));
    }

    #[test]
    fn user_paths_are_redacted_in_logs_and_named_values() {
        let policy = RedactionPolicy::default();
        let output = policy.redact_text(
            "config=/Users/alice/Library/Application Support/OpenStream/settings.json home=/home/alice/.config/openstream",
        );
        let named = policy.redact_class(
            RedactionClass::UserPath,
            r"C:\Users\alice\Secrets\pairing.json",
        );

        assert!(!output.contains("/Users/alice"));
        assert!(!output.contains("/home/alice"));
        assert!(!named.contains("C:\\Users\\alice"));
        assert!(output.contains("[REDACTED:user-path]"));
        assert_eq!(named, "[REDACTED:user-path]");
    }

    #[test]
    fn raw_logs_and_settings_are_redacted_and_bounded() {
        let policy = RedactionPolicy::new(256, 1024, 1024, 8).expect("test policy is valid");
        let mut bundle = DiagnosticBundle::new(manifest(), policy);
        bundle
            .add_log(
                "host",
                format!("token=log-secret {}", "diagnostic-line ".repeat(100)),
            )
            .expect("log is accepted");
        bundle
            .add_setting(
                "settings",
                "clipboard=clipboard-secret path=/Users/alice/private",
            )
            .expect("setting is accepted");

        let json = bundle.export_json().expect("JSON remains bounded");
        let text = bundle.export_text().expect("text remains bounded");
        assert!(json.len() <= 1024);
        assert!(text.len() <= 1024);
        assert!(!json.contains("log-secret"));
        assert!(!json.contains("clipboard-secret"));
        assert!(!json.contains("/Users/alice/private"));
        assert!(!text.contains("log-secret"));
        assert!(!text.contains("clipboard-secret"));
        assert!(!text.contains("/Users/alice/private"));
    }

    #[test]
    fn bundle_rejects_unrepresentable_export_without_truncating_json() {
        let policy = RedactionPolicy::new(256, 64, 64, 8).expect("test policy is valid");
        let mut bundle = DiagnosticBundle::new(manifest(), policy);
        bundle
            .add_status("transport", "connected")
            .expect("status is accepted");

        assert!(matches!(
            bundle.export_json(),
            Err(DiagnosticError::ExportTooLarge { .. })
        ));
        assert!(matches!(
            bundle.export_text(),
            Err(DiagnosticError::ExportTooLarge { .. })
        ));
    }

    #[test]
    fn release_manifest_is_typed_and_secret_free() {
        let bundle = DiagnosticBundle::new(manifest(), RedactionPolicy::default());
        let json = bundle.export_json().expect("manifest export is valid");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON is parseable");

        assert!(json.contains("aarch64-apple-darwin"));
        assert!(json.contains("0123456789abcdef0123456789abcdef01234567"));
        assert!(!json.contains("token"));
        assert!(!json.contains("private_key"));
        assert!(parsed["records"].is_array());
    }

    #[test]
    fn user_values_do_not_appear_in_debug_or_diagnostic_errors() {
        let token = "debug-token-secret";
        let user_path = "/Users/alice/private/settings.json";
        let mut bundle = DiagnosticBundle::new(manifest(), RedactionPolicy::default());
        bundle
            .add_log(
                "host",
                format!("Authorization: Bearer {token} path={user_path}"),
            )
            .expect("log is accepted");

        let debug = format!("{bundle:?}");
        let json = bundle.export_json().expect("JSON is valid");
        let text = bundle.export_text().expect("text is valid");
        let error = ReleaseManifest::new(
            "openstream",
            "0.1.0",
            user_path,
            "aarch64-apple-darwin",
            ReleaseProfile::Release,
        )
        .expect_err("a user path is not a valid release revision");
        let error_debug = format!("{error:?}");
        let error_text = error.to_string();

        for output in [&debug, &json, &text, &error_debug, &error_text] {
            assert!(!output.contains(token));
            assert!(!output.contains(user_path));
        }
    }
}
