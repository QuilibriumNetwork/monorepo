//! Optional node-local records appended only at the final database write.
//!
//! The projector sees the committed base and the final batch, never an
//! execution candidate. Its output cannot write outside its own namespace.

use rocksdb::{WriteBatch, DB};

const MAX_OUTPUT_BYTES: usize = 65 << 20;

pub trait LocalBatchProjection: Send + Sync {
    fn namespace(&self) -> &'static [u8];

    fn project(
        &self,
        view: &LocalProjectionRead<'_>,
        batch: &[u8],
        output: &mut LocalProjectionBatch,
    ) -> Result<(), String>;
}

/// Reads only. A projector must not reenter any database writer or owner lock.
pub struct LocalProjectionRead<'a>(pub(crate) &'a DB);

impl LocalProjectionRead<'_> {
    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.0.get(key)
    }

    /// Recover bounded pending local operations after a failed projection.
    /// None means that the prefix cannot be represented within the limits.
    pub fn prefix_entries(
        &self,
        prefix: &[u8],
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>, rocksdb::Error> {
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut iterator = self.0.raw_iterator();
        iterator.seek(prefix);
        while iterator.valid() {
            let Some(key) = iterator.key().filter(|key| key.starts_with(prefix)) else {
                break;
            };
            let Some(value) = iterator.value() else {
                break;
            };
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if entries.len() == max_entries || bytes > max_bytes {
                return Ok(None);
            }
            entries.push((key.to_vec(), value.to_vec()));
            iterator.next();
        }
        iterator.status()?;
        Ok(Some(entries))
    }
}

enum Mutation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    DeleteRange(Vec<u8>, Vec<u8>),
}

pub struct LocalProjectionBatch {
    namespace: &'static [u8],
    mutations: Vec<Mutation>,
    bytes: usize,
    rejected: bool,
}

impl LocalProjectionBatch {
    pub(crate) fn new(namespace: &'static [u8]) -> Self {
        Self {
            namespace,
            mutations: Vec::new(),
            bytes: 0,
            rejected: false,
        }
    }

    fn admit(&mut self, key: &[u8], extra: usize) -> Result<(), String> {
        let size = self
            .bytes
            .checked_add(key.len())
            .and_then(|n| n.checked_add(extra));
        if !key.starts_with(self.namespace) || size.is_none_or(|n| n > MAX_OUTPUT_BYTES) {
            self.rejected = true;
            return Err("local projection escaped its namespace or output limit".into());
        }
        self.bytes = size.unwrap();
        Ok(())
    }

    pub fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<(), String> {
        let (key, value) = (key.as_ref(), value.as_ref());
        self.admit(key, value.len())?;
        self.mutations
            .push(Mutation::Put(key.to_vec(), value.to_vec()));
        Ok(())
    }

    /// Stage an already assembled record without copying its buffers again.
    pub fn put_owned(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        self.admit(&key, value.len())?;
        self.mutations.push(Mutation::Put(key, value));
        Ok(())
    }

    pub fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<(), String> {
        let key = key.as_ref();
        self.admit(key, 0)?;
        self.mutations.push(Mutation::Delete(key.to_vec()));
        Ok(())
    }

    pub fn delete_range(
        &mut self,
        lower: impl AsRef<[u8]>,
        upper: impl AsRef<[u8]>,
    ) -> Result<(), String> {
        let (lower, upper) = (lower.as_ref(), upper.as_ref());
        if lower > upper || !upper.starts_with(self.namespace) {
            self.rejected = true;
            return Err("local projection range escaped its namespace".into());
        }
        self.admit(lower, upper.len())?;
        self.mutations
            .push(Mutation::DeleteRange(lower.to_vec(), upper.to_vec()));
        Ok(())
    }

    pub(crate) fn append(self, batch: &mut WriteBatch) -> bool {
        if self.rejected {
            return false;
        }
        for mutation in self.mutations {
            match mutation {
                Mutation::Put(key, value) => batch.put(key, value),
                Mutation::Delete(key) => batch.delete(key),
                Mutation::DeleteRange(lower, upper) => batch.delete_range(lower, upper),
            }
        }
        true
    }
}

/// On any projector failure this marker joins the original state write.
pub fn local_projection_invalid_key(namespace: &[u8]) -> Vec<u8> {
    [namespace, b"invalid"].concat()
}
