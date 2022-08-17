//! Nix expression serializer.

use serde::Serialize;

/// A Nix expression.
pub trait NixExpression: Send + Sync {
    /// Returns the full Nix expression to be evaluated.
    fn expression(&self) -> String;

    /// Returns whether this expression requires the use of flakes.
    fn requires_flakes(&self) -> bool {
        false
    }
}

/// A serialized Nix expression.
pub struct SerializedNixExpression(String);

impl NixExpression for String {
    fn expression(&self) -> String {
        self.clone()
    }
}

impl SerializedNixExpression {
    pub fn new<T>(data: T) -> Self
    where
        T: Serialize,
    {
        let json = serde_json::to_string(&data).expect("Could not serialize data");
        let quoted = nix_quote(&json);

        Self(quoted)
    }
}

impl NixExpression for SerializedNixExpression {
    fn expression(&self) -> String {
        format!("(builtins.fromJSON {})", &self.0)
    }
}

/// Turns a string into a quoted Nix string expression.
fn nix_quote(s: &str) -> String {
    let inner = s
        .replace('\\', r#"\\"#)
        .replace('"', r#"\""#)
        .replace("${", r#"\${"#);

    format!("\"{}\"", inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nix_quote() {
        let cases = [
            (r#"["a", "b"]"#, r#""[\"a\", \"b\"]""#),
            (
                r#"["\"a\"", "\"b\""]"#,
                r#""[\"\\\"a\\\"\", \"\\\"b\\\"\"]""#,
            ),
            (r#"${dontExpandMe}"#, r#""\${dontExpandMe}""#),
            (r#"\${dontExpandMe}"#, r#""\\\${dontExpandMe}""#),
        ];

        for (orig, quoted) in cases {
            assert_eq!(quoted, nix_quote(orig));
        }
    }
}
