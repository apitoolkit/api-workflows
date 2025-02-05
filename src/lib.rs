// src/lib.rs

// Re-export core APIs for users of the crate.
pub use base_request::{ConfigVariable, TestContext, run, run_json};

mod base_cli;
mod base_request;

use libc::c_char;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Arc;

/// Exposed via FFI. Expects three null‑terminated C strings:
///   - `content`: the test plan (in JSON)
///   - `collection_id`: the collection id (or an empty string if not used)
///   - `local_vars`: the local variables (in JSON)
///
/// Runs the test plan and returns a C string (which holds a JSON‑serialized result or error message).
///
/// # Safety
///
/// The caller is responsible for eventually freeing the returned C string by calling
/// `free_haskell_binding_result`.
#[no_mangle]
pub extern "C" fn haskell_binding(
    content: *const c_char,
    collection_id: *const c_char,
    local_vars: *const c_char,
) -> *mut c_char {
    // Validate that none of the incoming pointers are null.
    if content.is_null() || collection_id.is_null() || local_vars.is_null() {
        let err =
            CString::new("{\"error\": \"Null pointer passed in.\"}").expect("CString::new failed");
        return err.into_raw();
    }

    // Convert incoming C strings to Rust Strings.
    let cont_rs = unsafe { CStr::from_ptr(content) }
        .to_str()
        .unwrap_or_default()
        .to_owned();

    let col_path: Option<PathBuf> = unsafe { CStr::from_ptr(collection_id) }
        .to_str()
        .ok()
        .map(|s| PathBuf::from(s));

    let local_vars_str = unsafe { CStr::from_ptr(local_vars) }
        .to_str()
        .unwrap_or("{}");

    // Deserialize local variables from JSON.
    let local_vars_map: Vec<base_request::ConfigVariable> =
        serde_json::from_str(local_vars_str).unwrap_or_default();

    // Create a test context. Wrap string fields in Arc.
    let ctx = base_request::TestContext {
        file: Arc::new("haskell_binding".to_string()),
        file_source: Arc::new(cont_rs.clone()),
        should_log: false,
        ..Default::default()
    };

    // Create a Tokio runtime to run the async test plan.
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let result = rt.block_on(async {
        base_request::run_json(ctx, cont_rs, col_path, Some(local_vars_map)).await
    });

    // Serialize the result (or error) into JSON.
    let output_json = match result {
        Ok(res) => serde_json::to_string(&res)
            .unwrap_or_else(|e| format!("{{\"error\": \"Serialization error: {}\"}}", e)),
        Err(e) => format!("{{\"error\": \"{}\"}}", e),
    };

    // Convert the result into a CString and return its raw pointer.
    CString::new(output_json)
        .unwrap_or_else(|_| CString::new("{\"error\": \"CString conversion failed\"}").unwrap())
        .into_raw()
}

/// Frees the C string returned by `haskell_binding`.
#[no_mangle]
pub extern "C" fn free_haskell_binding_result(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // Explicitly drop the CString.
    let _ = unsafe { CString::from_raw(s) };
}
