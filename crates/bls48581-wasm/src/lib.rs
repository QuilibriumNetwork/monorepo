use wasm_bindgen::prelude::*;
use bls48581::{init, commit_raw, prove_raw, verify_raw, bls_keygen, bls_sign, bls_verify, bls_aggregate, prove_multiple, verify_multiple, Multiproof, BlsKeygenOutput, BlsAggregateOutput};

// Initialize the BLS48581 singleton
#[wasm_bindgen]
pub fn js_init() {
    init();
}

// Commit to data using KZG commitment
#[wasm_bindgen]
pub fn js_commit_raw(data: &str, poly_size: u64) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    let result = commit_raw(&data_bytes, poly_size);
    serde_json::json!(hex::encode(result)).to_string()
}

// Generate a proof for a specific index
#[wasm_bindgen]
pub fn js_prove_raw(data: &str, index: u64, poly_size: u64) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    let result = prove_raw(&data_bytes, index, poly_size);
    serde_json::json!(hex::encode(result)).to_string()
}

// Verify a proof
#[wasm_bindgen]
pub fn js_verify_raw(data: &str, commit: &str, index: u64, proof: &str, poly_size: u64) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    let commit_bytes = match hex::decode(commit) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode commit: {}", e)
        }).to_string()
    };
    
    let proof_bytes = match hex::decode(proof) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode proof: {}", e)
        }).to_string()
    };
    
    let result = verify_raw(&data_bytes, &commit_bytes, index, &proof_bytes, poly_size);
    serde_json::json!(result).to_string()
}

// Generate BLS key pair
#[wasm_bindgen]
pub fn js_bls_keygen() -> String {
    let result = bls_keygen();
    
    serde_json::json!({
        "secret_key": hex::encode(&result.secret_key),
        "public_key": hex::encode(&result.public_key),
        "proof_of_possession_sig": hex::encode(&result.proof_of_possession_sig)
    }).to_string()
}

// BLS sign
#[wasm_bindgen]
pub fn js_bls_sign(sk: &str, msg: &str, domain: &str) -> String {
    let sk_bytes = match hex::decode(sk) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode secret key: {}", e)
        }).to_string()
    };
    
    let msg_bytes = match hex::decode(msg) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode message: {}", e)
        }).to_string()
    };
    
    let domain_bytes = match hex::decode(domain) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode domain: {}", e)
        }).to_string()
    };
    
    let result = bls_sign(&sk_bytes, &msg_bytes, &domain_bytes);
    serde_json::json!(hex::encode(result)).to_string()
}

// BLS verify
#[wasm_bindgen]
pub fn js_bls_verify(pk: &str, sig: &str, msg: &str, domain: &str) -> String {
    let pk_bytes = match hex::decode(pk) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode public key: {}", e)
        }).to_string()
    };
    
    let sig_bytes = match hex::decode(sig) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode signature: {}", e)
        }).to_string()
    };
    
    let msg_bytes = match hex::decode(msg) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode message: {}", e)
        }).to_string()
    };
    
    let domain_bytes = match hex::decode(domain) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode domain: {}", e)
        }).to_string()
    };
    
    let result = bls_verify(&pk_bytes, &sig_bytes, &msg_bytes, &domain_bytes);
    serde_json::json!(result).to_string()
}

// BLS aggregate
#[wasm_bindgen]
pub fn js_bls_aggregate(pks: &str, sigs: &str) -> String {
    // Parse pks as array of hex encoded public keys
    let pks_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(pks);
    if let Err(e) = pks_result {
        return serde_json::json!({
            "error": format!("Failed to parse public keys: {}", e)
        }).to_string();
    }
    
    let mut decoded_pks = Vec::new();
    for pk in pks_result.unwrap() {
        match hex::decode(&pk) {
            Ok(decoded) => decoded_pks.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode public key: {}", e)
            }).to_string()
        }
    }
    
    // Parse sigs as array of hex encoded signatures
    let sigs_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(sigs);
    if let Err(e) = sigs_result {
        return serde_json::json!({
            "error": format!("Failed to parse signatures: {}", e)
        }).to_string();
    }
    
    let mut decoded_sigs = Vec::new();
    for sig in sigs_result.unwrap() {
        match hex::decode(&sig) {
            Ok(decoded) => decoded_sigs.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode signature: {}", e)
            }).to_string()
        }
    }
    
    let result = bls_aggregate(&decoded_pks, &decoded_sigs);
    
    serde_json::json!({
        "aggregate_public_key": hex::encode(&result.aggregate_public_key),
        "aggregate_signature": hex::encode(&result.aggregate_signature)
    }).to_string()
}

// Prove multiple commitments
#[wasm_bindgen]
pub fn js_prove_multiple(commitments: &str, polys: &str, indices: &str, poly_size: u64) -> String {
    // Parse commitments as array of hex encoded commitments
    let commitments_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(commitments);
    if let Err(e) = commitments_result {
        return serde_json::json!({
            "error": format!("Failed to parse commitments: {}", e)
        }).to_string();
    }
    
    let mut decoded_commitments = Vec::new();
    for commitment in commitments_result.unwrap() {
        match hex::decode(&commitment) {
            Ok(decoded) => decoded_commitments.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode commitment: {}", e)
            }).to_string()
        }
    }
    
    // Parse polys as array of hex encoded polynomials
    let polys_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(polys);
    if let Err(e) = polys_result {
        return serde_json::json!({
            "error": format!("Failed to parse polynomials: {}", e)
        }).to_string();
    }
    
    let mut decoded_polys = Vec::new();
    for poly in polys_result.unwrap() {
        match hex::decode(&poly) {
            Ok(decoded) => decoded_polys.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode polynomial: {}", e)
            }).to_string()
        }
    }
    
    // Parse indices as array of numbers
    let indices_result: Result<Vec<u64>, serde_json::Error> = serde_json::from_str(indices);
    if let Err(e) = indices_result {
        return serde_json::json!({
            "error": format!("Failed to parse indices: {}", e)
        }).to_string();
    }
    
    let result = prove_multiple(&decoded_commitments, &decoded_polys, &indices_result.unwrap(), poly_size);
    
    serde_json::json!({
        "d": hex::encode(&result.d),
        "proof": hex::encode(&result.proof)
    }).to_string()
}

// Verify multiple commitments
#[wasm_bindgen]
pub fn js_verify_multiple(commits: &str, y_bytes: &str, indices: &str, poly_size: u64, c_q_bytes: &str, proof_bytes: &str) -> String {
    // Parse commits as array of hex encoded commitments
    let commits_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(commits);
    if let Err(e) = commits_result {
        return serde_json::json!({
            "error": format!("Failed to parse commitments: {}", e)
        }).to_string();
    }
    
    let mut decoded_commits = Vec::new();
    for commit in commits_result.unwrap() {
        match hex::decode(&commit) {
            Ok(decoded) => decoded_commits.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode commitment: {}", e)
            }).to_string()
        }
    }
    
    // Parse y_bytes as array of hex encoded values
    let y_bytes_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(y_bytes);
    if let Err(e) = y_bytes_result {
        return serde_json::json!({
            "error": format!("Failed to parse y values: {}", e)
        }).to_string();
    }
    
    let mut decoded_y_bytes = Vec::new();
    for y in y_bytes_result.unwrap() {
        match hex::decode(&y) {
            Ok(decoded) => decoded_y_bytes.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode y value: {}", e)
            }).to_string()
        }
    }
    
    // Parse indices as array of numbers
    let indices_result: Result<Vec<u64>, serde_json::Error> = serde_json::from_str(indices);
    if let Err(e) = indices_result {
        return serde_json::json!({
            "error": format!("Failed to parse indices: {}", e)
        }).to_string();
    }
    
    // Decode c_q_bytes
    let c_q_decoded = match hex::decode(c_q_bytes) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode c_q_bytes: {}", e)
        }).to_string()
    };
    
    // Decode proof_bytes
    let proof_decoded = match hex::decode(proof_bytes) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode proof_bytes: {}", e)
        }).to_string()
    };
    
    let result = verify_multiple(&decoded_commits, &decoded_y_bytes, &indices_result.unwrap(), poly_size, &c_q_decoded, &proof_decoded);
    serde_json::json!(result).to_string()
}