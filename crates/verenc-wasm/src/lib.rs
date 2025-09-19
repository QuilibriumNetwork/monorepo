use wasm_bindgen::prelude::*;
use verenc::{new_verenc_proof, new_verenc_proof_encrypt_only, verenc_verify, verenc_compress, verenc_recover, chunk_data_for_verenc, combine_chunked_data, verenc_verify_statement, VerencProofAndBlindingKey, VerencProof, CompressedCiphertext, VerencDecrypt, VerencCiphertext, VerencShare};

// Create a new verifiable encryption proof
#[wasm_bindgen]
pub fn js_new_verenc_proof(data: &str) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    if data_bytes.len() != 56 {
        return serde_json::json!({
            "error": "Data must be exactly 56 bytes"
        }).to_string();
    }
    
    let result = new_verenc_proof(data_bytes);
    
    // Check if the result is empty (error case)
    if result.blinding_key.is_empty() {
        return serde_json::json!({
            "error": "Failed to create verenc proof"
        }).to_string();
    }
    
    serde_json::json!({
        "blinding_key": hex::encode(&result.blinding_key),
        "blinding_pubkey": hex::encode(&result.blinding_pubkey),
        "decryption_key": hex::encode(&result.decryption_key),
        "encryption_key": hex::encode(&result.encryption_key),
        "statement": hex::encode(&result.statement),
        "challenge": hex::encode(&result.challenge),
        "polycom": result.polycom.iter().map(|p| hex::encode(p)).collect::<Vec<String>>(),
        "ctexts": result.ctexts.iter().map(|c| serde_json::json!({
            "c1": hex::encode(&c.c1),
            "c2": hex::encode(&c.c2),
            "i": c.i
        })).collect::<Vec<serde_json::Value>>(),
        "shares_rands": result.shares_rands.iter().map(|s| serde_json::json!({
            "s1": hex::encode(&s.s1),
            "s2": hex::encode(&s.s2),
            "i": s.i
        })).collect::<Vec<serde_json::Value>>()
    }).to_string()
}

// Create a new verifiable encryption proof with existing encryption key
#[wasm_bindgen]
pub fn js_new_verenc_proof_encrypt_only(data: &str, encryption_key: &str) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    if data_bytes.len() != 56 {
        return serde_json::json!({
            "error": "Data must be exactly 56 bytes"
        }).to_string();
    }
    
    let encryption_key_bytes = match hex::decode(encryption_key) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode encryption key: {}", e)
        }).to_string()
    };
    
    let result = new_verenc_proof_encrypt_only(data_bytes, encryption_key_bytes);
    
    // Check if the result is empty (error case)
    if result.blinding_key.is_empty() {
        return serde_json::json!({
            "error": "Failed to create verenc proof"
        }).to_string();
    }
    
    serde_json::json!({
        "blinding_key": hex::encode(&result.blinding_key),
        "blinding_pubkey": hex::encode(&result.blinding_pubkey),
        "decryption_key": hex::encode(&result.decryption_key),
        "encryption_key": hex::encode(&result.encryption_key),
        "statement": hex::encode(&result.statement),
        "challenge": hex::encode(&result.challenge),
        "polycom": result.polycom.iter().map(|p| hex::encode(p)).collect::<Vec<String>>(),
        "ctexts": result.ctexts.iter().map(|c| serde_json::json!({
            "c1": hex::encode(&c.c1),
            "c2": hex::encode(&c.c2),
            "i": c.i
        })).collect::<Vec<serde_json::Value>>(),
        "shares_rands": result.shares_rands.iter().map(|s| serde_json::json!({
            "s1": hex::encode(&s.s1),
            "s2": hex::encode(&s.s2),
            "i": s.i
        })).collect::<Vec<serde_json::Value>>()
    }).to_string()
}

// Verify a verifiable encryption proof
#[wasm_bindgen]
pub fn js_verenc_verify(proof: &str) -> String {
    let proof_data: serde_json::Value = match serde_json::from_str(proof) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to parse proof: {}", e)
        }).to_string()
    };
    
    // Decode blinding_pubkey
    let blinding_pubkey = match hex::decode(proof_data["blinding_pubkey"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding_pubkey: {}", e)
        }).to_string()
    };
    
    // Decode encryption_key
    let encryption_key = match hex::decode(proof_data["encryption_key"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode encryption_key: {}", e)
        }).to_string()
    };
    
    // Decode statement
    let statement = match hex::decode(proof_data["statement"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode statement: {}", e)
        }).to_string()
    };
    
    // Decode challenge
    let challenge = match hex::decode(proof_data["challenge"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode challenge: {}", e)
        }).to_string()
    };
    
    let empty = Vec::new();
    // Decode polycom
    let polycom_array = proof_data["polycom"].as_array().unwrap_or(&empty);
    let mut polycom = Vec::new();
    for p in polycom_array {
        match hex::decode(p.as_str().unwrap_or("")) {
            Ok(b) => polycom.push(b),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode polycom: {}", e)
            }).to_string()
        }
    }
    
    // Decode ctexts
    let ctexts_array = proof_data["ctexts"].as_array().unwrap_or(&empty);
    let mut ctexts = Vec::new();
    for c in ctexts_array {
        let c1 = match hex::decode(c["c1"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c1: {}", e)
            }).to_string()
        };
        let c2 = match hex::decode(c["c2"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c2: {}", e)
            }).to_string()
        };
        let i = c["i"].as_u64().unwrap_or(0);
        ctexts.push(VerencCiphertext { c1, c2, i });
    }
    
    // Decode shares_rands
    let shares_array = proof_data["shares_rands"].as_array().unwrap_or(&empty);
    let mut shares_rands = Vec::new();
    for s in shares_array {
        let s1 = match hex::decode(s["s1"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode share s1: {}", e)
            }).to_string()
        };
        let s2 = match hex::decode(s["s2"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode share s2: {}", e)
            }).to_string()
        };
        let i = s["i"].as_u64().unwrap_or(0);
        shares_rands.push(VerencShare { s1, s2, i });
    }
    
    let verenc_proof = VerencProof {
        blinding_pubkey,
        encryption_key,
        statement,
        challenge,
        polycom,
        ctexts,
        shares_rands,
    };
    
    let result = verenc_verify(verenc_proof);
    serde_json::json!(result).to_string()
}

// Compress a verifiable encryption proof
#[wasm_bindgen]
pub fn js_verenc_compress(proof: &str) -> String {
    let proof_data: serde_json::Value = match serde_json::from_str(proof) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to parse proof: {}", e)
        }).to_string()
    };
    
    // Parse proof same as js_verenc_verify
    let blinding_pubkey = match hex::decode(proof_data["blinding_pubkey"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding_pubkey: {}", e)
        }).to_string()
    };
    
    let encryption_key = match hex::decode(proof_data["encryption_key"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode encryption_key: {}", e)
        }).to_string()
    };
    
    let statement = match hex::decode(proof_data["statement"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode statement: {}", e)
        }).to_string()
    };
    
    let challenge = match hex::decode(proof_data["challenge"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode challenge: {}", e)
        }).to_string()
    };

    let empty = Vec::new();
    
    let polycom_array = proof_data["polycom"].as_array().unwrap_or(&empty);
    let mut polycom = Vec::new();
    for p in polycom_array {
        match hex::decode(p.as_str().unwrap_or("")) {
            Ok(b) => polycom.push(b),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode polycom: {}", e)
            }).to_string()
        }
    }
    
    let ctexts_array = proof_data["ctexts"].as_array().unwrap_or(&empty);
    let mut ctexts = Vec::new();
    for c in ctexts_array {
        let c1 = match hex::decode(c["c1"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c1: {}", e)
            }).to_string()
        };
        let c2 = match hex::decode(c["c2"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c2: {}", e)
            }).to_string()
        };
        let i = c["i"].as_u64().unwrap_or(0);
        ctexts.push(VerencCiphertext { c1, c2, i });
    }
    
    let shares_array = proof_data["shares_rands"].as_array().unwrap_or(&empty);
    let mut shares_rands = Vec::new();
    for s in shares_array {
        let s1 = match hex::decode(s["s1"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode share s1: {}", e)
            }).to_string()
        };
        let s2 = match hex::decode(s["s2"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode share s2: {}", e)
            }).to_string()
        };
        let i = s["i"].as_u64().unwrap_or(0);
        shares_rands.push(VerencShare { s1, s2, i });
    }
    
    let verenc_proof = VerencProof {
        blinding_pubkey,
        encryption_key,
        statement,
        challenge,
        polycom,
        ctexts,
        shares_rands,
    };
    
    let result = verenc_compress(verenc_proof);
    
    // Check if result is empty (error case)
    if result.ctexts.is_empty() {
        return serde_json::json!({
            "error": "Failed to compress proof"
        }).to_string();
    }
    
    serde_json::json!({
        "ctexts": result.ctexts.iter().map(|c| serde_json::json!({
            "c1": hex::encode(&c.c1),
            "c2": hex::encode(&c.c2),
            "i": c.i
        })).collect::<Vec<serde_json::Value>>(),
        "aux": result.aux.iter().map(|a| hex::encode(a)).collect::<Vec<String>>()
    }).to_string()
}

// Recover data from compressed ciphertext
#[wasm_bindgen]
pub fn js_verenc_recover(recovery: &str) -> String {
    let recovery_data: serde_json::Value = match serde_json::from_str(recovery) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to parse recovery data: {}", e)
        }).to_string()
    };
    
    // Decode blinding_pubkey
    let blinding_pubkey = match hex::decode(recovery_data["blinding_pubkey"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding_pubkey: {}", e)
        }).to_string()
    };
    
    // Decode decryption_key
    let decryption_key = match hex::decode(recovery_data["decryption_key"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode decryption_key: {}", e)
        }).to_string()
    };
    
    // Decode statement
    let statement = match hex::decode(recovery_data["statement"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode statement: {}", e)
        }).to_string()
    };
    
    let empty = Vec::new();

    // Decode ciphertexts
    let ctexts_array = recovery_data["ciphertexts"]["ctexts"].as_array().unwrap_or(&empty);
    let mut ctexts = Vec::new();
    for c in ctexts_array {
        let c1 = match hex::decode(c["c1"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c1: {}", e)
            }).to_string()
        };
        let c2 = match hex::decode(c["c2"].as_str().unwrap_or("")) {
            Ok(b) => b,
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode ctext c2: {}", e)
            }).to_string()
        };
        let i = c["i"].as_u64().unwrap_or(0);
        ctexts.push(VerencCiphertext { c1, c2, i });
    }
    
    // Decode aux
    let aux_array = recovery_data["ciphertexts"]["aux"].as_array().unwrap_or(&empty);
    let mut aux = Vec::new();
    for a in aux_array {
        match hex::decode(a.as_str().unwrap_or("")) {
            Ok(b) => aux.push(b),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode aux: {}", e)
            }).to_string()
        }
    }
    
    let ciphertexts = CompressedCiphertext { ctexts, aux };
    
    let verenc_decrypt = VerencDecrypt {
        blinding_pubkey,
        decryption_key,
        statement,
        ciphertexts,
    };
    
    let result = verenc_recover(verenc_decrypt);
    
    if result.is_empty() {
        return serde_json::json!({
            "error": "Failed to recover data"
        }).to_string();
    }
    
    serde_json::json!(hex::encode(result)).to_string()
}

// Chunk data for verifiable encryption
#[wasm_bindgen]
pub fn js_chunk_data_for_verenc(data: &str) -> String {
    let data_bytes = match hex::decode(data) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode data: {}", e)
        }).to_string()
    };
    
    let result = chunk_data_for_verenc(data_bytes);
    
    let chunks: Vec<String> = result.iter().map(|chunk| hex::encode(chunk)).collect();
    serde_json::json!(chunks).to_string()
}

// Combine chunked data
#[wasm_bindgen]
pub fn js_combine_chunked_data(chunks: &str) -> String {
    // Parse chunks as array of hex encoded chunks
    let chunks_result: Result<Vec<String>, serde_json::Error> = serde_json::from_str(chunks);
    if let Err(e) = chunks_result {
        return serde_json::json!({
            "error": format!("Failed to parse chunks: {}", e)
        }).to_string();
    }
    
    let mut decoded_chunks = Vec::new();
    for chunk in chunks_result.unwrap() {
        match hex::decode(&chunk) {
            Ok(decoded) => decoded_chunks.push(decoded),
            Err(e) => return serde_json::json!({
                "error": format!("Failed to decode chunk: {}", e)
            }).to_string()
        }
    }
    
    let result = combine_chunked_data(decoded_chunks);
    serde_json::json!(hex::encode(result)).to_string()
}

// Verify statement
#[wasm_bindgen]
pub fn js_verenc_verify_statement(input: &str, blinding_pubkey: &str, statement: &str) -> String {
    let input_bytes = match hex::decode(input) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode input: {}", e)
        }).to_string()
    };
    
    let blinding_pubkey_bytes = match hex::decode(blinding_pubkey) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode blinding_pubkey: {}", e)
        }).to_string()
    };
    
    let statement_bytes = match hex::decode(statement) {
        Ok(b) => b,
        Err(e) => return serde_json::json!({
            "error": format!("Failed to decode statement: {}", e)
        }).to_string()
    };
    
    let result = verenc_verify_statement(input_bytes, blinding_pubkey_bytes, statement_bytes);
    serde_json::json!(result).to_string()
}