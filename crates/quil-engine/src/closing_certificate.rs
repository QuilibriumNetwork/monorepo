//! Durable delivery of an authenticated terminal-seal finalization.
use std::io::{self, Read, Write};
use std::path::PathBuf;

use quil_cw_consensus::handoff::{verify_seal, Seal, Session, MAX_RECORD_BYTES};
use quil_execution::global_intrinsic::handoff::CertificateSubmission;

pub(crate) struct ClosingCertificate {
    path: PathBuf,
    session: Session,
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

impl ClosingCertificate {
    pub fn new(path: PathBuf, session: Session) -> Self {
        Self { path, session }
    }

    fn authenticate(&self, submission: &CertificateSubmission) -> io::Result<()> {
        verify_seal(&self.session, &submission.seal.request, &submission.seal, &submission.certificate)
            .ok_or_else(|| invalid("closing certificate does not authenticate under its session"))?;
        Ok(())
    }

    pub fn load(&self) -> io::Result<Option<CertificateSubmission>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("closing certificate record exceeds size limit"));
        }
        let submission = CertificateSubmission::from_canonical_bytes(&bytes).map_err(invalid)?;
        self.authenticate(&submission)?;
        Ok(Some(submission))
    }

    pub fn persist(&self, seal: &[u8], certificate: &[u8]) -> io::Result<()> {
        if certificate.len() > MAX_RECORD_BYTES {
            return Err(invalid("closing certificate exceeds size limit"));
        }
        let submission = CertificateSubmission {
            seal: Seal::decode(seal).map_err(invalid)?, certificate: certificate.to_vec(),
        };
        self.authenticate(&submission)?;
        let parent = self.path.parent().ok_or_else(|| invalid("closing certificate has no parent directory"))?;
        if let Some(existing) = self.load()? {
            if existing.seal != submission.seal {
                return Err(invalid("another terminal seal is already recorded for this session"));
            }
            // Complete a rename whose directory sync was interrupted.
            std::fs::File::open(&self.path)?.sync_all()?;
            return std::fs::File::open(parent)?.sync_all();
        }
        let bytes = submission.to_canonical_bytes().map_err(invalid)?;
        std::fs::create_dir_all(parent)?;
        let staged = self.path.with_extension("closing-staged");
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(staged, &self.path)?;
        std::fs::File::open(parent)?.sync_all()
    }
}
