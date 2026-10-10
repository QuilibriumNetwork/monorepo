//! Local clock record codecs shared by durable and tentative stores.
use quil_types::{
    error::{QuilError, Result},
    store::{RequestOutcome, RequestStatus},
};

fn malformed() -> QuilError {
    QuilError::Serialization("malformed clock frame outcomes".into())
}

pub(crate) fn encode_outcomes(outcomes: &[RequestOutcome], max_bytes: usize) -> Result<Vec<u8>> {
    let count = u32::try_from(outcomes.len()).map_err(|_| malformed())?;
    let mut length = 4usize;
    for outcome in outcomes {
        u32::try_from(outcome.error.len()).map_err(|_| malformed())?;
        length = length
            .checked_add(5)
            .and_then(|n| n.checked_add(outcome.error.len()))
            .filter(|n| *n <= max_bytes)
            .ok_or_else(|| QuilError::ExecutionUnavailable("clock outcomes byte limit".into()))?;
    }
    if length > max_bytes {
        return Err(QuilError::ExecutionUnavailable(
            "clock outcomes byte limit".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&count.to_be_bytes());
    for outcome in outcomes {
        bytes.push(outcome.status.as_u8());
        bytes.extend_from_slice(&(outcome.error.len() as u32).to_be_bytes());
        bytes.extend_from_slice(outcome.error.as_bytes());
    }
    Ok(bytes)
}

pub(crate) fn decode_outcomes(bytes: &[u8]) -> Result<Vec<RequestOutcome>> {
    let count =
        u32::from_be_bytes(bytes.get(..4).ok_or_else(malformed)?.try_into().unwrap()) as usize;
    // Every entry needs a status byte and a four-byte string length. Reject a
    // forged count before it can request a large Vec allocation.
    if count > bytes.len().saturating_sub(4) / 5 {
        return Err(malformed());
    }
    let mut cursor = 4usize;
    let mut outcomes = Vec::with_capacity(count);
    for _ in 0..count {
        let status = match bytes.get(cursor) {
            Some(0) => RequestStatus::Succeeded,
            Some(1) => RequestStatus::Rejected,
            Some(2) => RequestStatus::Failed,
            Some(3) => RequestStatus::Skipped,
            _ => return Err(malformed()),
        };
        cursor += 1;
        let end = cursor.checked_add(4).ok_or_else(malformed)?;
        let length = u32::from_be_bytes(
            bytes
                .get(cursor..end)
                .ok_or_else(malformed)?
                .try_into()
                .unwrap(),
        ) as usize;
        cursor = end;
        let end = cursor.checked_add(length).ok_or_else(malformed)?;
        let error = std::str::from_utf8(bytes.get(cursor..end).ok_or_else(malformed)?)
            .map_err(|_| malformed())?
            .to_owned();
        cursor = end;
        outcomes.push(RequestOutcome { status, error });
    }
    if cursor != bytes.len() {
        return Err(malformed());
    }
    Ok(outcomes)
}

pub(crate) fn decode_legacy_outcomes(bytes: Option<Vec<u8>>) -> Result<Vec<RequestOutcome>> {
    match bytes {
        // Legacy outcome rows collided with 24-byte certified-state records.
        // This shape is ambiguous; do not guess that it represents outcomes.
        Some(bytes) if bytes.len() != 24 => decode_outcomes(&bytes),
        _ => Ok(Vec::new()),
    }
}
