use wasm_bindgen::prelude::*;
use bulletproofs::{generate_input_commitments, generate_range_proof, verify_range_proof, sum_check, scalar_mult_point, scalar_mult, scalar_inverse, keygen, scalar_mult_hash_to_scalar, hash_to_scalar, scalar_addition, scalar_subtraction, scalar_to_point, alt_generator, point_addition, point_subtraction, sign_hidden, verify_hidden, sign_simple, verify_simple, RangeProofResult};

// Bulletproofs wrapper functions

#[wasm_bindgen]
pub fn js_generate_range_proof(values: &str, blinding: &str, bit_size: u64) -> String {
    // Parse values as array of hex encoded byte arrays
    let values_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(values);
    if let Err(e) = values_result {
        return serde_json::json!({
            "error": e.to_string()
        }).to_string();
    }
    
    let mut decoded_values = Vec::new();
    for value in values_result.unwrap() {
        match hex::decode(&value) {
            Ok(decoded) => decoded_values.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode value: {}", e)
            }).to_string()
        }
    }
    
    // Decode blinding
    let blinding_bytes = match hex::decode(blinding) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding: {}", e)
        }).to_string()
    };
    
    let result = generate_range_proof(decoded_values, blinding_bytes, bit_size);
        
    return serde_json::json!({
        "proof": hex::encode(&result.proof),
        "commitment": hex::encode(&result.commitment),
        "blinding": hex::encode(&result.blinding)
    }).to_string();
}

#[wasm_bindgen]
pub fn js_verify_range_proof(proof: &str, commitment: &str, bit_size: u64) -> String {
    let proof_bytes = match hex::decode(proof) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode proof: {}", e)
        }).to_string()
    };
    
    let commitment_bytes = match hex::decode(commitment) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode commitment: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(verify_range_proof(proof_bytes, commitment_bytes, bit_size)).to_string();
}

#[wasm_bindgen]
pub fn js_sum_check(input_commitments: &str, additional_input_values: &str, output_commitments: &str, additional_output_values: &str) -> String {
    // Helper function to decode array of hex strings
    let decode_array = |json_str: &str, name: &str| -> Result<Vec<Vec<u8>>, String> {
        let array: Vec<String> = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse {}: {}", name, e))?;
        
        let mut decoded = Vec::new();
        for (i, value) in array.iter().enumerate() {
            match hex::decode(value) {
                Ok(bytes) => decoded.push(bytes),
                Err(e) => return Err(format!("Failed to decode {} at index {}: {}", name, i, e))
            }
        }
        Ok(decoded)
    };
    
    let input_comms = match decode_array(input_commitments, "input_commitments") {
        Ok(v) => v,
        Err(e) => return serde_json::json!({"error": e}).to_string()
    };
    
    let add_inputs = match decode_array(additional_input_values, "additional_input_values") {
        Ok(v) => v,
        Err(e) => return serde_json::json!({"error": e}).to_string()
    };
    
    let output_comms = match decode_array(output_commitments, "output_commitments") {
        Ok(v) => v,
        Err(e) => return serde_json::json!({"error": e}).to_string()
    };
    
    let add_outputs = match decode_array(additional_output_values, "additional_output_values") {
        Ok(v) => v,
        Err(e) => return serde_json::json!({"error": e}).to_string()
    };
    
    return serde_json::json!(sum_check(input_comms, add_inputs, output_comms, add_outputs)).to_string();
}

#[wasm_bindgen]
pub fn js_generate_input_commitments(values: &str, blinding: &str) -> String {
    let values_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(values);
    if let Err(e) = values_result {
        return serde_json::json!({
            "error": e.to_string()
        }).to_string();
    }
    
    let mut decoded_values = Vec::new();
    for value in values_result.unwrap() {
        match hex::decode(&value) {
            Ok(decoded) => decoded_values.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode value: {}", e)
            }).to_string()
        }
    }
    
    let blinding_bytes = match hex::decode(blinding) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(generate_input_commitments(decoded_values, blinding_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_keygen() -> String {
    return serde_json::json!(hex::encode(keygen())).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_to_point(input: &str) -> String {
    let input_bytes = match hex::decode(input) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode input: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_to_point(input_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_alt_generator() -> String {
  return serde_json::json!(hex::encode(alt_generator())).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_addition(lhs: &str, rhs: &str) -> String {
    let lhs_bytes = match hex::decode(lhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode lhs: {}", e)
        }).to_string()
    };
    
    let rhs_bytes = match hex::decode(rhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode rhs: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_addition(lhs_bytes, rhs_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_mult(lhs: &str, rhs: &str) -> String {
    let lhs_bytes = match hex::decode(lhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode lhs: {}", e)
        }).to_string()
    };
    
    let rhs_bytes = match hex::decode(rhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode rhs: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_mult(lhs_bytes, rhs_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_mult_point(input_scalar: &str, public_point: &str) -> String {
    let scalar_bytes = match hex::decode(input_scalar) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode scalar: {}", e)
        }).to_string()
    };
    
    let point_bytes = match hex::decode(public_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_mult_point(scalar_bytes, point_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_inverse(input_scalar: &str) -> String {
    let scalar_bytes = match hex::decode(input_scalar) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode scalar: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_inverse(scalar_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_subtraction(lhs: &str, rhs: &str) -> String {
    let lhs_bytes = match hex::decode(lhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode lhs: {}", e)
        }).to_string()
    };
    
    let rhs_bytes = match hex::decode(rhs) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode rhs: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_subtraction(lhs_bytes, rhs_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_scalar_mult_hash_to_scalar(input_scalar: &str, public_point: &str) -> String {
    let scalar_bytes = match hex::decode(input_scalar) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode scalar: {}", e)
        }).to_string()
    };
    
    let point_bytes = match hex::decode(public_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(scalar_mult_hash_to_scalar(scalar_bytes, point_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_hash_to_scalar(input: &str) -> String {
    let input_bytes = match hex::decode(input) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode input: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(hash_to_scalar(input_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_point_addition(input_point: &str, public_point: &str) -> String {
    let input_bytes = match hex::decode(input_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode input point: {}", e)
        }).to_string()
    };
    
    let point_bytes = match hex::decode(public_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode public point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(point_addition(input_bytes, point_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_point_subtraction(input_point: &str, public_point: &str) -> String {
    let input_bytes = match hex::decode(input_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode input point: {}", e)
        }).to_string()
    };
    
    let point_bytes = match hex::decode(public_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode public point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(point_subtraction(input_bytes, point_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_sign_hidden(x: &str, t: &str, a: &str, r: &str) -> String {
    let x_bytes = match hex::decode(x) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode x: {}", e)
        }).to_string()
    };
    
    let t_bytes = match hex::decode(t) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode t: {}", e)
        }).to_string()
    };
    
    let a_bytes = match hex::decode(a) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode a: {}", e)
        }).to_string()
    };
    
    let r_bytes = match hex::decode(r) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode r: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(sign_hidden(x_bytes, t_bytes, a_bytes, r_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_sign_simple(secret: &str, message: &str) -> String {
    let secret_bytes = match hex::decode(secret) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode secret: {}", e)
        }).to_string()
    };
    
    let message_bytes = match hex::decode(message) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode message: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(hex::encode(sign_simple(secret_bytes, message_bytes))).to_string();
}

#[wasm_bindgen]
pub fn js_verify_simple(message: &str, signature: &str, public_point: &str) -> String {
    let message_bytes = match hex::decode(message) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode message: {}", e)
        }).to_string()
    };
    
    let signature_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode signature: {}", e)
        }).to_string()
    };
    
    let point_bytes = match hex::decode(public_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode public point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(verify_simple(message_bytes, signature_bytes, point_bytes)).to_string();
}

#[wasm_bindgen]
pub fn js_verify_hidden(c: &str, t: &str, s1: &str, s2: &str, s3: &str, p_point: &str, c_point: &str) -> String {
    let c_bytes = match hex::decode(c) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode c: {}", e)
        }).to_string()
    };
    
    let t_bytes = match hex::decode(t) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode t: {}", e)
        }).to_string()
    };
    
    let s1_bytes = match hex::decode(s1) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode s1: {}", e)
        }).to_string()
    };
    
    let s2_bytes = match hex::decode(s2) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode s2: {}", e)
        }).to_string()
    };
    
    let s3_bytes = match hex::decode(s3) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode s3: {}", e)
        }).to_string()
    };
    
    let p_point_bytes = match hex::decode(p_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode p_point: {}", e)
        }).to_string()
    };
    
    let c_point_bytes = match hex::decode(c_point) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode c_point: {}", e)
        }).to_string()
    };
    
    return serde_json::json!(verify_hidden(c_bytes, t_bytes, s1_bytes, s2_bytes, s3_bytes, p_point_bytes, c_point_bytes)).to_string();
}
