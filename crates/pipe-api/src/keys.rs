//! Reviewed account-key settings. Missing fields and explicit null have different effects.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Number, Value};
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Field<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}
impl<T> Field<T> {
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}
impl<T: Serialize> Serialize for Field<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Value(v) => v.serialize(s),
            _ => s.serialize_none(),
        }
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            Some(v) => Self::Value(v),
            None => Self::Null,
        })
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Field::is_missing")]
    pub label: Field<String>,
    #[serde(default, skip_serializing_if = "Field::is_missing")]
    pub hard_cap_usd: Field<Number>,
    #[serde(default, skip_serializing_if = "Field::is_missing")]
    pub daily_cap_usd: Field<Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_retention: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}
impl Settings {
    /// Compare requested settings only. Creation also compares omitted defaults.
    /// Metered spend, use timestamps and computed remaining credit are not settings.
    pub fn matches(&self, row: &Value, create: bool) -> bool {
        fn field<T: Serialize>(field: &Field<T>, value: &Value, create: bool) -> bool {
            match field {
                Field::Missing => !create || value.is_null(),
                Field::Null => value.is_null(),
                Field::Value(v) => serde_json::to_value(v).is_ok_and(|v| match (&v, value) {
                    (Value::Number(a), Value::Number(b)) => decimal_equal(a, b),
                    _ => v == *value,
                }),
            }
        }
        field(&self.label, &row["label"], create)
            && field(&self.hard_cap_usd, &row["hard_cap_usd"], create)
            && field(&self.daily_cap_usd, &row["daily_cap_usd"], create)
            && self.allowed_models.as_ref().map_or(
                !create || row["allowed_models"].as_array().is_none_or(Vec::is_empty),
                |v| {
                    row["allowed_models"].as_array().map_or(v.is_empty(), |a| {
                        *a == v
                            .iter()
                            .map(|s| Value::String(s.clone()))
                            .collect::<Vec<_>>()
                    })
                },
            )
            && self
                .no_retention
                .map_or(!create || row["no_retention"] == false, |v| {
                    row["no_retention"] == v
                })
            && self
                .disabled
                .map_or(!create || row["disabled"] == false, |v| {
                    row["disabled"] == v
                })
    }
}

// The legacy service renders caps as JSON floats (10 becomes 10.0). Compare
// decimal values without rounding either input through a binary float.
fn decimal_equal(a: &Number, b: &Number) -> bool {
    fn normalized(n: &Number) -> Option<(bool, String, i64)> {
        let text = n.to_string();
        let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((&text, "0"));
        let mut exponent: i64 = exponent.parse().ok()?;
        let negative = mantissa.starts_with('-');
        let mantissa = mantissa.trim_start_matches('-');
        if let Some((_, fraction)) = mantissa.split_once('.') {
            exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
        }
        let digits = mantissa.replace('.', "");
        let digits = digits.trim_start_matches('0');
        if digits.is_empty() {
            return Some((false, "0".into(), 0));
        }
        let trimmed = digits.trim_end_matches('0');
        exponent = exponent.checked_add(i64::try_from(digits.len() - trimmed.len()).ok()?)?;
        Some((negative, trimmed.into(), exponent))
    }
    a == b || normalized(a).is_some_and(|a| Some(a) == normalized(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_compares_decimal_caps_without_rounding_and_preserves_null() {
        let patch: Settings =
            serde_json::from_str(r#"{"label":null,"hard_cap_usd":10,"daily_cap_usd":1e-2}"#)
                .unwrap();
        let roundtrip = serde_json::to_value(&patch).unwrap();
        assert!(roundtrip["label"].is_null());
        assert!(roundtrip.get("no_retention").is_none());
        assert!(patch.matches(
            &serde_json::json!({"label":null,"hard_cap_usd":10.0,"daily_cap_usd":0.01}),
            false
        ));
        let rounded: Settings =
            serde_json::from_str(r#"{"hard_cap_usd":1.0000000000000001}"#).unwrap();
        assert!(!rounded.matches(&serde_json::json!({"hard_cap_usd":1.0}), false));
        assert!(!patch.matches(
            &serde_json::json!({"label":"later","hard_cap_usd":10.0,"daily_cap_usd":0.01}),
            false
        ));
    }
}
