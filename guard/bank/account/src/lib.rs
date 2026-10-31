//! Demo bank account service: routing and fake data. The HTTP server is in main.rs.
//!
//! `regex` (the seeded vulnerable crate) is imported and called here, but only ever on a
//! constant pattern applied to constant demo data; no request input reaches it.

use regex::Regex;

/// A fake customer profile. All data is invented.
pub fn profile_json() -> String {
    // regex is exercised on constant input: validate the demo account number format.
    let re = Regex::new(r"^DE\d{2} \d{4} \d{4} \d{4} \d{2}$").unwrap();
    let account = "DE00 0000 0000 0042 00";
    let valid = re.is_match(account);
    format!(
        "{{\"name\":\"Demo Customer\",\"account\":\"{}\",\"iban_valid\":{},\"tier\":\"gold\"}}",
        account, valid
    )
}

pub fn statements_json() -> String {
    "{\"account\":\"DE00 0000 0000 0042 00\",\"statements\":[\
{\"month\":\"2026-09\",\"in\":2100.0,\"out\":1870.5},\
{\"month\":\"2026-10\",\"in\":2100.0,\"out\":1663.2}]}"
        .to_string()
}

/// Route a request. Returns (status, content_type, body).
pub fn route(method: &str, path: &str) -> (u16, &'static str, String) {
    match (method, path) {
        ("GET", "/health") => (200, "application/json", "{\"status\":\"ok\"}".to_string()),
        ("GET", "/") => (200, "application/json", "{\"service\":\"account\"}".to_string()),
        ("GET", "/profile") => (200, "application/json", profile_json()),
        ("GET", "/statements") => (200, "application/json", statements_json()),
        _ => (404, "application/json", "{\"error\":\"not found\"}".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok() {
        assert_eq!(route("GET", "/health").0, 200);
    }

    #[test]
    fn profile_validates_the_account_with_regex() {
        let (status, _, body) = route("GET", "/profile");
        assert_eq!(status, 200);
        assert!(body.contains("\"iban_valid\":true"));
    }

    #[test]
    fn unknown_path_is_404() {
        assert_eq!(route("GET", "/nope").0, 404);
    }
}
