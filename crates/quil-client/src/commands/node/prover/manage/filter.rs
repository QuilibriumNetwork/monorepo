//! Numeric column-filter expression parsing/matching. Port of
//! `parseNumericExpr` / `matchesNumericExpr` in `manage_model.go`.

enum NumericOp {
    Gt(f64),
    Ge(f64),
    Lt(f64),
    Le(f64),
    Eq(f64),
    In(Vec<f64>),
    None,
}

fn parse_numeric_expr(expr: &str) -> NumericOp {
    let expr = expr.trim();
    if expr.is_empty() {
        return NumericOp::None;
    }
    // Order matters: check two-char prefixes before one-char.
    for prefix in [">=", "<=", ">", "<", "="] {
        if let Some(rest) = expr.strip_prefix(prefix) {
            let rest = rest.trim();
            let Ok(v) = rest.parse::<f64>() else {
                return NumericOp::None;
            };
            return match prefix {
                ">=" => NumericOp::Ge(v),
                "<=" => NumericOp::Le(v),
                ">" => NumericOp::Gt(v),
                "<" => NumericOp::Lt(v),
                "=" => NumericOp::Eq(v),
                _ => NumericOp::None,
            };
        }
    }
    // Comma-separated value list.
    let mut vals = Vec::new();
    for p in expr.split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let Ok(v) = p.parse::<f64>() else {
            return NumericOp::None;
        };
        vals.push(v);
    }
    if !vals.is_empty() {
        NumericOp::In(vals)
    } else {
        NumericOp::None
    }
}

/// `matchesNumericExpr` — true if `val` satisfies the filter expression.
pub fn matches_numeric_expr(val: f64, expr: &str) -> bool {
    if expr.is_empty() {
        return true;
    }
    match parse_numeric_expr(expr) {
        NumericOp::Gt(t) => val > t,
        NumericOp::Ge(t) => val >= t,
        NumericOp::Lt(t) => val < t,
        NumericOp::Le(t) => val <= t,
        NumericOp::Eq(t) => val == t,
        NumericOp::In(values) => {
            let parts: Vec<&str> = expr.split(',').collect();
            for (i, v) in values.iter().enumerate() {
                if val == *v {
                    return true;
                }
                // For decimal filter values, compare formatted strings to
                // absorb float precision (e.g. "47.1" matches 47.09375).
                if let Some(part) = parts.get(i) {
                    let part = part.trim();
                    if let Some(dot) = part.find('.') {
                        let decimals = part.len() - dot - 1;
                        if format!("{:.*}", decimals, val) == part {
                            return true;
                        }
                    }
                }
            }
            false
        }
        NumericOp::None => true, // unparseable = no filter
    }
}

#[cfg(test)]
mod tests {
    use super::matches_numeric_expr;

    #[test]
    fn comparison_ops() {
        assert!(matches_numeric_expr(48.0, "> 47"));
        assert!(!matches_numeric_expr(47.0, "> 47"));
        assert!(matches_numeric_expr(47.0, ">= 47"));
        assert!(matches_numeric_expr(10.0, "< 100"));
        assert!(matches_numeric_expr(5.0, "<=5"));
        assert!(matches_numeric_expr(3.0, "=3"));
        assert!(!matches_numeric_expr(4.0, "=3"));
    }

    #[test]
    fn value_list_and_decimal_match() {
        assert!(matches_numeric_expr(5.0, "1,5,7"));
        assert!(!matches_numeric_expr(6.0, "1,5,7"));
        // Decimal display-string match absorbs float precision.
        assert!(matches_numeric_expr(47.09375, "47.1"));
    }

    #[test]
    fn empty_and_unparseable_are_no_filter() {
        assert!(matches_numeric_expr(42.0, ""));
        assert!(matches_numeric_expr(42.0, "garbage"));
    }
}
