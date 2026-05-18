//! # PDF format adapter
//!
//! Embeds mark_id in PDF document metadata using annotation-layer injection.
//!
//! Two embedding locations (mirrors the Python `oversight_core.formats.pdf`):
//!   1. PDF `/Info` dictionary custom fields (`/OversightMark`, `/OversightIssuer`,
//!      `/OversightFileId`) -- fast to read, easy to strip.
//!   2. (Future) Invisible text watermark on every page via zero-width unicode
//!      in a hidden text object -- survives metadata stripping.
//!
//! ## Security constraints
//!
//! - **No executable content**: the adapter MUST NOT inject JavaScript (`/JS`),
//!   actions (`/AA`, `/OpenAction`), or form submissions. Only passive metadata
//!   and annotation-layer text are permitted.
//! - **No launch actions**: `/Launch`, `/URI` with non-https schemes, `/GoTo`
//!   to external files are all forbidden.
//!
//! ## Dependencies
//!
//! Uses the `lopdf` crate for low-level PDF object manipulation. This gives
//! full control over what gets written (unlike higher-level wrappers that
//! might inject unwanted objects).

use crate::{FormatAdapter, FormatError, WatermarkCandidate};
use lopdf::content::{Content, Operation};
use lopdf::{decode_text_string, Dictionary, Document, Object, StringFormat};

/// PDF `/Info` dictionary key for the oversight mark_id.
const METADATA_KEY: &str = "OversightMark";
/// PDF `/Info` dictionary key for the issuer ID.
const ISSUER_KEY: &str = "OversightIssuer";
/// PDF `/Info` dictionary key for the file ID.
const FILE_ID_KEY: &str = "OversightFileId";

/// PDF format adapter.
pub struct PdfAdapter;

impl FormatAdapter for PdfAdapter {
    fn name(&self) -> &str {
        "pdf"
    }

    fn extensions(&self) -> &[&str] {
        &["pdf"]
    }

    fn can_handle(&self, data: &[u8]) -> bool {
        // PDF magic: %PDF-
        data.len() >= 5 && &data[0..5] == b"%PDF-"
    }

    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
        embed_pdf_metadata(data, mark_id, None, None)
    }

    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError> {
        let meta = extract_pdf_metadata(data)?;
        let mut candidates = Vec::new();
        if let Some(mark_hex) = meta.mark_id {
            if let Ok(mark_bytes) = hex::decode(&mark_hex) {
                candidates.push(WatermarkCandidate {
                    mark_id: mark_bytes,
                    layer: "metadata".into(),
                    confidence: 1.0,
                });
            }
        }
        Ok(candidates)
    }

    fn normalize_for_fingerprint(&self, data: &[u8]) -> Result<String, FormatError> {
        extract_text_for_fingerprint(data)
    }
}

// ---------------------------------------------------------------------------
// Metadata extraction result
// ---------------------------------------------------------------------------

/// Oversight metadata extracted from a PDF.
#[derive(Debug, Clone, Default)]
pub struct PdfOversightMeta {
    pub mark_id: Option<String>,
    pub issuer_id: Option<String>,
    pub file_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Embed
// ---------------------------------------------------------------------------

/// Embed mark_id (and optional issuer/file IDs) into the PDF `/Info` dictionary.
///
/// SECURITY: This function only writes passive string metadata. It does NOT
/// inject JavaScript, actions, or any executable PDF objects.
pub fn embed_pdf_metadata(
    pdf_bytes: &[u8],
    mark_id: &[u8],
    issuer_id: Option<&str>,
    file_id: Option<&str>,
) -> Result<Vec<u8>, FormatError> {
    let mut doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    // Validate: refuse to process PDFs with JavaScript or launch actions.
    // This is defense-in-depth: we don't add them, but we also refuse to
    // be a vehicle for passing through existing malicious content.
    security_check(&doc)?;

    // Get or create the /Info dictionary
    // lopdf stores trailer info; we access it via the document's trailer
    let mark_hex = hex::encode(mark_id);

    // Set metadata fields in the document info dictionary
    doc.trailer.remove(b"Info"); // Remove old info reference if any

    let mut info_dict = Dictionary::new();
    info_dict.set(
        METADATA_KEY,
        Object::String(mark_hex.into_bytes(), StringFormat::Literal),
    );
    if let Some(issuer) = issuer_id {
        // Sanitize: strip any PDF-special characters from issuer_id
        let sanitized = sanitize_pdf_string(issuer);
        info_dict.set(
            ISSUER_KEY,
            Object::String(sanitized.into_bytes(), StringFormat::Literal),
        );
    }
    if let Some(fid) = file_id {
        let sanitized = sanitize_pdf_string(fid);
        info_dict.set(
            FILE_ID_KEY,
            Object::String(sanitized.into_bytes(), StringFormat::Literal),
        );
    }

    let info_id = doc.add_object(Object::Dictionary(info_dict));
    doc.trailer.set("Info", Object::Reference(info_id));

    let mut output = Vec::new();
    doc.save_to(&mut output)
        .map_err(|e| FormatError::EmbedFailed(format!("PDF write error: {}", e)))?;

    Ok(output)
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

/// Extract Oversight metadata from the PDF `/Info` dictionary.
pub fn extract_pdf_metadata(pdf_bytes: &[u8]) -> Result<PdfOversightMeta, FormatError> {
    let doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    let mut meta = PdfOversightMeta::default();

    // Try to read the /Info dictionary from the trailer
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok(info_id) = info_ref.as_reference() {
            if let Ok(info_obj) = doc.get_object(info_id) {
                if let Ok(dict) = info_obj.as_dict() {
                    meta.mark_id = get_string_from_dict(dict, METADATA_KEY);
                    meta.issuer_id = get_string_from_dict(dict, ISSUER_KEY);
                    meta.file_id = get_string_from_dict(dict, FILE_ID_KEY);
                }
            }
        }
    }

    Ok(meta)
}

pub fn extract_text_for_fingerprint(pdf_bytes: &[u8]) -> Result<String, FormatError> {
    let doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    let page_numbers: Vec<u32> = doc.get_pages().keys().copied().collect();
    if !page_numbers.is_empty() {
        if let Ok(text) = doc.extract_text(&page_numbers) {
            let normalized = normalize_pdf_text_parts(text.lines().map(str::to_owned));
            if !normalized.is_empty() {
                return Ok(normalized);
            }
        }
    }

    let mut text_parts: Vec<String> = Vec::new();
    for page_id in doc.page_iter() {
        if let Ok(content) = doc.get_page_content(page_id) {
            text_parts.extend(extract_text_from_content_stream(&content));
        }
    }

    Ok(normalize_pdf_text_parts(text_parts))
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// Validate that the PDF does not contain executable content.
///
/// We refuse to process PDFs with JavaScript or auto-launch actions to
/// prevent the adapter from being used as a vector for malicious content.
fn security_check(doc: &Document) -> Result<(), FormatError> {
    for (_id, obj) in doc.objects.iter() {
        if let Ok(dict) = obj.as_dict() {
            if dict.has(b"JS") || dict.has(b"JavaScript") {
                return Err(FormatError::Malformed(
                    "PDF contains JavaScript -- refusing to process for security".into(),
                ));
            }
            if let Ok(s_type) = dict.get(b"S") {
                if let Ok(name) = s_type.as_name_str() {
                    match name {
                        "Launch" | "JavaScript" => {
                            return Err(FormatError::Malformed(
                                "PDF contains Launch/JavaScript action -- refusing to process"
                                    .into(),
                            ));
                        }
                        "URI" => {
                            if let Ok(uri_obj) = dict.get(b"URI") {
                                if let Some(uri) = pdf_object_string(uri_obj) {
                                    let lower = uri.to_ascii_lowercase();
                                    if !lower.starts_with("https://") {
                                        return Err(FormatError::Malformed(
                                            "PDF contains unsafe URI action -- refusing to process"
                                                .into(),
                                        ));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            if dict.has(b"OpenAction") || dict.has(b"AA") {
                if let Ok(action) = dict.get(b"OpenAction").or(dict.get(b"AA")) {
                    if let Ok(action_dict) = action.as_dict() {
                        if action_dict.has(b"JS") || action_dict.has(b"JavaScript") {
                            return Err(FormatError::Malformed(
                                "PDF contains JavaScript auto-action -- refusing to process".into(),
                            ));
                        }
                        // Check for Launch actions
                        if let Ok(s_type) = action_dict.get(b"S") {
                            if let Ok(name) = s_type.as_name_str() {
                                if name == "Launch" || name == "JavaScript" {
                                    return Err(FormatError::Malformed(
                                        "PDF contains Launch/JavaScript action -- refusing to process".into(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn pdf_object_string(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
        Object::Name(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => None,
    }
}

/// Sanitize a string for safe inclusion in PDF metadata.
/// Strips control characters and PDF-special delimiters that could cause injection.
fn sanitize_pdf_string(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Allow printable ASCII and common Unicode, reject control chars
            // and PDF-special characters that could break the string context.
            !c.is_control() && *c != '(' && *c != ')' && *c != '\\'
        })
        .collect()
}

/// Helper to get a string value from a PDF dictionary.
fn get_string_from_dict(dict: &Dictionary, key: &str) -> Option<String> {
    dict.get(key.as_bytes()).ok().and_then(|obj| match obj {
        Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
        _ => None,
    })
}

fn extract_text_from_content_stream(content: &[u8]) -> Vec<String> {
    if let Ok(parsed) = Content::decode(content) {
        return extract_text_from_operations(&parsed.operations);
    }
    extract_text_from_literal_bytes(content)
}

fn extract_text_from_operations(operations: &[Operation]) -> Vec<String> {
    let mut parts = Vec::new();
    for operation in operations {
        match operation.operator.as_str() {
            "Tj" | "'" => {
                if let Some(text) = operation.operands.first().and_then(object_text) {
                    push_pdf_text(&mut parts, text);
                }
            }
            "\"" => {
                if let Some(text) = operation.operands.last().and_then(object_text) {
                    push_pdf_text(&mut parts, text);
                }
            }
            "TJ" => {
                if let Some(Object::Array(items)) = operation.operands.first() {
                    push_pdf_text(&mut parts, text_from_array(items));
                }
            }
            _ => {}
        }
    }
    parts
}

fn object_text(obj: &Object) -> Option<String> {
    match obj {
        Object::String(_, _) => decode_text_string(obj).ok(),
        _ => None,
    }
}

fn text_from_array(items: &[Object]) -> String {
    let mut text = String::new();
    for item in items {
        match item {
            Object::String(_, _) => {
                if let Some(part) = object_text(item) {
                    text.push_str(&part);
                }
            }
            Object::Integer(value) if *value < -100 => text.push(' '),
            Object::Real(value) if *value < -100.0 => text.push(' '),
            _ => {}
        }
    }
    text
}

fn push_pdf_text(parts: &mut Vec<String>, text: String) {
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_owned());
    }
}

fn normalize_pdf_text_parts<I>(parts: I) -> String
where
    I: IntoIterator<Item = String>,
{
    parts
        .into_iter()
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_text_from_literal_bytes(content: &[u8]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut i = 0;
    let lossy = String::from_utf8_lossy(content);
    let chars: Vec<char> = lossy.chars().collect();
    while i < chars.len() {
        if chars[i] == '(' {
            let mut depth = 1;
            let mut j = i + 1;
            while j < chars.len() && depth > 0 {
                if chars[j] == '(' && (j == 0 || chars[j - 1] != '\\') {
                    depth += 1;
                } else if chars[j] == ')' && (j == 0 || chars[j - 1] != '\\') {
                    depth -= 1;
                }
                j += 1;
            }
            if depth == 0 {
                let text: String = chars[i + 1..j - 1].iter().collect();
                if !text.is_empty() {
                    parts.push(text);
                }
                i = j;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Stream};

    #[test]
    fn pdf_adapter_can_handle() {
        let adapter = PdfAdapter;
        assert!(adapter.can_handle(b"%PDF-1.4 rest of pdf"));
        assert!(adapter.can_handle(b"%PDF-2.0"));
        assert!(!adapter.can_handle(b"PK\x03\x04"));
        assert!(!adapter.can_handle(b"Hello, world!"));
        assert!(!adapter.can_handle(b""));
    }

    #[test]
    fn pdf_adapter_extensions() {
        let adapter = PdfAdapter;
        assert_eq!(adapter.extensions(), &["pdf"]);
    }

    #[test]
    fn sanitize_pdf_string_strips_dangerous_chars() {
        assert_eq!(sanitize_pdf_string("hello(world)"), "helloworld");
        assert_eq!(sanitize_pdf_string("test\\injection"), "testinjection");
        assert_eq!(sanitize_pdf_string("normal text 123"), "normal text 123");
    }

    #[test]
    fn security_check_rejects_indirect_launch_action_objects() {
        let mut doc = Document::with_version("1.7");
        let mut action = lopdf::Dictionary::new();
        action.set("S", Object::Name(b"Launch".to_vec()));
        doc.objects.insert((1, 0), Object::Dictionary(action));
        assert!(security_check(&doc).is_err());
    }

    #[test]
    fn security_check_rejects_unsafe_uri_actions() {
        let mut doc = Document::with_version("1.7");
        let mut action = lopdf::Dictionary::new();
        action.set("S", Object::Name(b"URI".to_vec()));
        action.set(
            "URI",
            Object::String(b"file:///C:/secret".to_vec(), StringFormat::Literal),
        );
        doc.objects.insert((1, 0), Object::Dictionary(action));
        assert!(security_check(&doc).is_err());
    }

    #[test]
    fn extract_text_from_content_stream_parses_pdf_text_ops() {
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tj", vec![Object::string_literal("Hello")]),
                Operation::new(
                    "TJ",
                    vec![Object::Array(vec![
                        Object::string_literal("Rust"),
                        Object::Integer(-120),
                        Object::string_literal("Port"),
                    ])],
                ),
                Operation::new("'", vec![Object::string_literal("Next line")]),
                Operation::new(
                    "\"",
                    vec![
                        Object::Integer(0),
                        Object::Integer(0),
                        Object::string_literal("Quoted op"),
                    ],
                ),
                Operation::new("ET", vec![]),
            ],
        };
        let encoded = content.encode().unwrap();
        let parts = extract_text_from_content_stream(&encoded);
        assert_eq!(parts, vec!["Hello", "Rust Port", "Next line", "Quoted op"]);
    }

    #[test]
    fn extract_text_for_fingerprint_reads_page_text() {
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), Object::Integer(12)]),
                Operation::new("Td", vec![Object::Integer(72), Object::Integer(720)]),
                Operation::new("Tj", vec![Object::string_literal("Oversight Rust")]),
                Operation::new(
                    "TJ",
                    vec![Object::Array(vec![
                        Object::string_literal("PDF"),
                        Object::Integer(-120),
                        Object::string_literal("Extraction"),
                    ])],
                ),
                Operation::new("ET", vec![]),
            ],
        };
        let pdf = minimal_pdf(content);
        let text = extract_text_for_fingerprint(&pdf).unwrap();
        assert!(text.contains("Oversight Rust"));
        assert!(text.contains("PDF Extraction"));
    }

    fn minimal_pdf(content: Content<Vec<Operation>>) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! {
                "F1" => font_id,
            },
        });
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
                "Resources" => resources_id,
                "MediaBox" => vec![
                    Object::Integer(0),
                    Object::Integer(0),
                    Object::Integer(595),
                    Object::Integer(842),
                ],
            }),
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut output = Vec::new();
        doc.save_to(&mut output).unwrap();
        output
    }
}
