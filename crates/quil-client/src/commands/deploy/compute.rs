//! `qclient deploy compute <QCLFile> [RDFFile] [-d <domain>]`.
//!
//! Port of `client/cmd/deploy/deploy.go` `DeployComputeCmd`. Two modes:
//!
//! - **No `--domain`**: deploy a *new* compute intrinsic. Builds a
//!   `ComputeDeploy` from the CLI's deploy keys (+ optional RDF schema) and
//!   sends it on the zero domain — same shape as `deploy hypergraph`/`token`
//!   (the node materializes read/write/owner from the config; no inner sig).
//! - **`--domain <addr>`**: deploy QCL *code* to an existing compute domain.
//!   The circuit is the **raw QCL file bytes** (the client does not compile QCL
//!   — compilation happens node-side), wrapped in a `CodeDeployment`.
//!
//! If no RDF file is given and the QCL path ends in `.qcl`, an adjacent
//! `<name>.rdf` is used when present (mirrors Go's inference).

use quil_types::proto::compute::{CodeDeployment, ComputeConfiguration, ComputeDeploy};
use quil_types::proto::global::{message_request::Request, MessageRequest};

use super::DeployCtx;

pub async fn run(
    dc: &DeployCtx,
    domain_arg: &str,
    qcl_file: &str,
    rdf_file: Option<&str>,
) -> anyhow::Result<()> {
    if !domain_arg.is_empty() {
        return deploy_code_to_existing_domain(dc, domain_arg, qcl_file).await;
    }
    deploy_new_compute_intrinsic(dc, qcl_file, rdf_file).await
}

/// Deploy a new compute intrinsic (no domain) — `ComputeDeploy` on zero domain.
async fn deploy_new_compute_intrinsic(
    dc: &DeployCtx,
    qcl_file: &str,
    rdf_file: Option<&str>,
) -> anyhow::Result<()> {
    // Resolve the RDF schema: explicit arg, else an inferred `.qcl`→`.rdf`
    // sibling if it exists.
    let rdf_path = match rdf_file {
        Some(p) => Some(p.to_string()),
        None => {
            if let Some(stem) = qcl_file.strip_suffix(".qcl") {
                let inferred = format!("{stem}.rdf");
                if std::path::Path::new(&inferred).exists() {
                    println!("Inferred RDF file: {inferred}");
                    Some(inferred)
                } else {
                    None
                }
            } else {
                None
            }
        }
    };
    let rdf_schema = match rdf_path {
        Some(p) => std::fs::read(&p).map_err(|e| anyhow::anyhow!("read RDF file {p:?}: {e}"))?,
        None => Vec::new(),
    };

    let keys = dc.deploy_keys()?;
    let deploy = ComputeDeploy {
        config: Some(ComputeConfiguration {
            read_public_key: keys.read,
            write_public_key: keys.write,
            owner_public_key: keys.owner,
        }),
        rdf_schema,
    };

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::ComputeDeploy(deploy)),
        timestamp: 0,
    };
    dc.send_deploy(&mut client, request).await?;

    println!("Compute intrinsic deployed successfully");
    Ok(())
}

/// Deploy QCL code to an existing compute domain — `CodeDeployment` with the
/// raw QCL bytes as the circuit.
async fn deploy_code_to_existing_domain(
    dc: &DeployCtx,
    domain_arg: &str,
    qcl_file: &str,
) -> anyhow::Result<()> {
    let circuit =
        std::fs::read(qcl_file).map_err(|e| anyhow::anyhow!("read QCL file {qcl_file:?}: {e}"))?;
    let domain = dc.resolve_address(domain_arg, 32)?;

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::CodeDeploy(CodeDeployment {
            circuit,
            input_types: Vec::new(),
            output_types: Vec::new(),
            domain: domain.clone(),
        })),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &dc.key_manager, domain.clone(), request).await?;

    println!("Code deployed successfully");
    println!("  Domain: {}", hex::encode(&domain));
    Ok(())
}
