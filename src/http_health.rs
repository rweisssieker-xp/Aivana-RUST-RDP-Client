//! Bounded form/session health checks. Values and cookies stay in worker memory.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read};
pub type Values = BTreeMap<String, String>;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    #[default]
    Get,
    Post,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    #[serde(default)]
    pub method: Method,
    #[serde(default)]
    pub form: Values,
    #[serde(default)]
    pub secret_fields: Values,
    #[serde(default)]
    pub json_equals: BTreeMap<String, serde_json::Value>,
}
impl Options {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self, tls: bool) -> Result<()> {
        ensure!(
            self.form.len() + self.secret_fields.len() <= 32 && self.json_equals.len() <= 16,
            "HTTP-Feldgrenze überschritten"
        );
        ensure!(
            self.method == Method::Post || (self.form.is_empty() && self.secret_fields.is_empty()),
            "GET kann keine Formulare senden"
        );
        ensure!(
            tls || self.secret_fields.is_empty(),
            "Secret-Slots benötigen HTTPS"
        );
        for (k, v) in self.form.iter().chain(&self.secret_fields) {
            ensure!(
                !k.is_empty()
                    && k.len() <= 128
                    && v.len() <= 4096
                    && !k.chars().any(char::is_control)
                    && !v.chars().any(char::is_control),
                "Ungültiges Formularfeld"
            );
        }
        for (k, v) in &self.secret_fields {
            ensure!(
                !self.form.contains_key(k) && !v.is_empty() && v.len() <= 128,
                "Doppeltes Feld oder ungültiger Secret-Slot"
            );
        }
        for (pointer, value) in &self.json_equals {
            ensure!(
                pointer.len() <= 512
                    && (pointer.is_empty() || pointer.starts_with('/'))
                    && !pointer.chars().any(char::is_control),
                "Ungültiger JSON-Pointer"
            );
            let mut chars = pointer.chars();
            while let Some(c) = chars.next() {
                if c == '~' {
                    ensure!(
                        matches!(chars.next(), Some('0' | '1')),
                        "Ungültiges JSON-Pointer-Escape"
                    );
                }
            }
            ensure!(
                value.is_null()
                    || value.is_boolean()
                    || value.as_i64().is_some_and(|n| (-9_007_199_254_740_991
                        ..=9_007_199_254_740_991)
                        .contains(&n))
                    || value.as_str().is_some_and(|s| s.len() <= 1024),
                "JSON-Assertions unterstützen String, Bool, null oder Ganzzahlen von -9007199254740991 bis 9007199254740991"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 16384,
            "HTTP-Prüfschritt zu groß"
        );
        Ok(())
    }
    pub fn validate_values(&self, values: &Values) -> Result<()> {
        for slot in self.secret_fields.values() {
            ensure!(
                values.get(slot).is_some_and(|v| !v.is_empty()
                    && v.len() <= 4096
                    && !v.chars().any(char::is_control)),
                "Secret-Slot fehlt oder ist ungültig: {slot}"
            );
        }
        let size: usize = self
            .form
            .iter()
            .map(|(k, v)| k.len() + v.len() + 2)
            .chain(
                self.secret_fields
                    .iter()
                    .map(|(k, slot)| k.len() + values[slot].len() + 2),
            )
            .sum();
        ensure!(size <= 32768, "Formular überschreitet 32 KiB");
        Ok(())
    }
}
fn cookies(headers: &reqwest::header::HeaderMap, jar: &mut Values, tls: bool) -> Result<()> {
    for h in headers.get_all(reqwest::header::SET_COOKIE) {
        let raw = h.to_str()?;
        ensure!(
            raw.len() <= 4096 && raw.is_ascii(),
            "Cookie zu groß oder nicht ASCII"
        );
        let parts: Vec<_> = raw.split(';').map(str::trim).collect();
        let attrs = &parts[1..];
        ensure!(
            attrs.iter().any(|s| s.eq_ignore_ascii_case("path=/"))
                && !attrs
                    .iter()
                    .any(|s| s.to_ascii_lowercase().starts_with("domain=")
                        || (s.to_ascii_lowercase().starts_with("path=")
                            && !s.eq_ignore_ascii_case("path=/"))),
            "Nur hosteigene Path=/-Session-Cookies erlaubt"
        );
        let (name, value) = parts[0]
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Cookie ungültig"))?;
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && value
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && !b"\";,\\".contains(&b)),
            "Cookie-Zeichen ungültig"
        );
        if attrs.iter().any(|s| s.eq_ignore_ascii_case("secure")) && !tls {
            continue;
        }
        let age = attrs.iter().find_map(|s| {
            s.split_once('=')
                .filter(|(k, _)| k.eq_ignore_ascii_case("max-age"))
                .map(|(_, v)| v)
        });
        if age.is_some_and(|a| a.parse::<i64>().is_ok_and(|n| n <= 0)) {
            jar.remove(name);
            continue;
        }
        ensure!(
            age.is_none()
                && !attrs
                    .iter()
                    .any(|s| s.to_ascii_lowercase().starts_with("expires=")),
            "Nur Sitzungscookies ohne Ablaufzeit unterstützt"
        );
        ensure!(
            jar.len() < 32 || jar.contains_key(name),
            "Cookie-Grenze überschritten"
        );
        jar.insert(name.into(), value.into());
    }
    Ok(())
}
pub fn execute(
    url: &str,
    status: u16,
    contains: &str,
    steps: &[super::HttpGetStep],
    values: &Values,
) -> Result<bool> {
    let base = reqwest::Url::parse(url)?;
    for step in steps {
        step.options.validate_values(values)?;
    }
    let first = super::HttpGetStep {
        path: base.path().into(),
        status,
        contains: contains.into(),
        options: Options::default(),
    };
    let mut jar = Values::new();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    for step in std::iter::once(&first).chain(steps) {
        let mut endpoint = base.clone();
        endpoint.set_path(&step.path);
        ensure!(endpoint.origin() == base.origin(), "HTTP-Origin geändert");
        let mut fields = step.options.form.clone();
        for (field, slot) in &step.options.secret_fields {
            fields.insert(field.clone(), values[slot].clone());
        }
        let mut request = match step.options.method {
            Method::Get => client.get(endpoint),
            Method::Post => client.post(endpoint).form(&fields),
        };
        if !jar.is_empty() {
            request = request.header(
                reqwest::header::COOKIE,
                jar.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let response = request.send()?;
        if response.status().as_u16() != step.status {
            return Ok(false);
        }
        cookies(response.headers(), &mut jar, base.scheme() == "https")?;
        let mut body = vec![];
        response.take(65537).read_to_end(&mut body)?;
        ensure!(body.len() <= 65536, "HTTP-Antwort zu groß");
        let body = String::from_utf8_lossy(&body);
        if !body.contains(&step.contains) {
            return Ok(false);
        }
        if !step.options.json_equals.is_empty() {
            let json: serde_json::Value = serde_json::from_str(&body)?;
            ensure!(json_depth(&json) <= 32, "JSON-Verschachtelungsgrenze");
            for (pointer, expected) in &step.options.json_equals {
                if json.pointer(pointer) != Some(expected) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(v) => 1 + v.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(v) => 1 + v.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integer_assertions_reject_fractional_or_imprecise_expectations() {
        for raw in ["0", "3", "-3", "9007199254740991", "-9007199254740991"] {
            let mut options = Options::default();
            options
                .json_equals
                .insert("/count".into(), serde_json::from_str(raw).unwrap());
            assert!(options.validate(true).is_ok(), "{raw}");
        }
        for raw in [
            "3.0",
            "3e0",
            "0.5",
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551615",
            "[]",
            "{}",
        ] {
            let mut options = Options::default();
            options
                .json_equals
                .insert("/count".into(), serde_json::from_str(raw).unwrap());
            assert!(options.validate(true).is_err(), "{raw}");
        }
    }
    #[test]
    fn secret_slots_fail_before_io_and_values_never_serialize() {
        let mut options = Options::default();
        options.method = Method::Post;
        options
            .secret_fields
            .insert("password".into(), "login".into());
        assert!(options.validate(false).is_err());
        assert!(options.validate(true).is_ok());
        assert!(options.validate_values(&Values::new()).is_err());
        let values = Values::from([("login".into(), "runtime-private-value".into())]);
        assert!(options.validate_values(&values).is_ok());
        assert!(
            !serde_json::to_string(&options)
                .unwrap()
                .contains("runtime-private-value")
        );
    }
    #[test]
    fn cookie_scope_and_persistence_are_not_weakened() {
        for raw in [
            "sid=x; Path=/; Domain=evil.invalid",
            "sid=x; Path=/other",
            "sid=x; Path=/; Max-Age=60",
            "sid=x; Path=/; Expires=Thu, 01 Jan 2037 00:00:00 GMT",
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::SET_COOKIE, raw.parse().unwrap());
            assert!(cookies(&headers, &mut Values::new(), true).is_err());
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            "sid=x; Path=/; Secure".parse().unwrap(),
        );
        let mut jar = Values::new();
        cookies(&headers, &mut jar, false).unwrap();
        assert!(jar.is_empty());
        cookies(&headers, &mut jar, true).unwrap();
        assert_eq!(jar.get("sid").unwrap(), "x");
    }
}
