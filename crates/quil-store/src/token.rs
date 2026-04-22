use std::sync::Arc;

use prost::Message;

use quil_types::error::{QuilError, Result};
use quil_types::proto::node;
use quil_types::store;

use crate::encoding;

/// RocksDB-backed token/balance store.
pub struct RocksTokenStore {
    db: Arc<rocksdb::DB>,
}

impl RocksTokenStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }

    /// Helper: extract the implicit account address from a Coin's owner field.
    /// Returns an empty slice if the owner is missing or not an implicit account.
    fn owner_address(coin: &node::Coin) -> &[u8] {
        match coin.owner.as_ref().and_then(|r| r.account.as_ref()) {
            Some(node::account_ref::Account::ImplicitAccount(acct)) => &acct.address,
            _ => &[],
        }
    }

    /// Create a RocksDB iterator over a key range. This materializes all
    /// entries into memory so the returned iterator is Send + 'static.
    fn make_iter(&self, lower: &[u8], upper: &[u8]) -> RocksTokenIterator {
        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower.to_vec());
        read_opts.set_iterate_upper_bound(upper.to_vec());

        let iter = self.db.iterator_opt(rocksdb::IteratorMode::Start, read_opts);
        let mut entries = Vec::new();
        for item in iter {
            match item {
                Ok((k, v)) => entries.push((k.to_vec(), v.to_vec())),
                Err(_) => break,
            }
        }

        RocksTokenIterator { entries, pos: -1 }
    }
}

/// Materialized key-value iterator for range scans.
struct RocksTokenIterator {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    pos: i64,
}

impl RocksTokenIterator {
    fn valid(&self) -> bool {
        self.pos >= 0 && (self.pos as usize) < self.entries.len()
    }

    fn first(&mut self) -> bool {
        if self.entries.is_empty() {
            self.pos = -1;
            return false;
        }
        self.pos = 0;
        true
    }

    fn next(&mut self) -> bool {
        self.pos += 1;
        self.valid()
    }

    fn key(&self) -> &[u8] {
        if self.valid() {
            &self.entries[self.pos as usize].0
        } else {
            &[]
        }
    }

    fn value(&self) -> &[u8] {
        if self.valid() {
            &self.entries[self.pos as usize].1
        } else {
            &[]
        }
    }
}

impl store::TokenStore for RocksTokenStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn store::Transaction>> {
        Ok(Box::new(crate::RocksTransaction {
            db: self.db.clone(),
            batch: std::sync::Mutex::new(rocksdb::WriteBatch::default()),
        }))
    }

    // -----------------------------------------------------------------
    // Coins
    // -----------------------------------------------------------------

    fn get_coins_for_owner(
        &self,
        owner: &[u8],
    ) -> Result<(Vec<u64>, Vec<Vec<u8>>, Vec<node::Coin>)> {
        let lower = encoding::coin_by_owner_key(owner, &[0x00; 32]);
        let upper = encoding::coin_by_owner_key(owner, &[0xff; 32]);
        let mut iter = self.make_iter(&lower, &upper);

        let mut frame_numbers = Vec::new();
        let mut addresses = Vec::new();
        let mut coins = Vec::new();

        if !iter.first() {
            return Ok((frame_numbers, addresses, coins));
        }

        loop {
            let value = iter.value();
            if value.len() < 8 {
                return Err(QuilError::Store(
                    "coin value too short for frame number".into(),
                ));
            }
            let frame_number = u64::from_be_bytes(value[..8].try_into().unwrap());
            let coin = node::Coin::decode(&value[8..])
                .map_err(|e| QuilError::Serialization(e.to_string()))?;

            frame_numbers.push(frame_number);
            // The owner-indexed key is [0x07, 0x01, owner(32), address(32)].
            // Extract the coin address from the key suffix.
            let key = iter.key();
            let addr_start = 2 + owner.len();
            let mut addr = vec![0u8; 32];
            if key.len() >= addr_start + 32 {
                addr.copy_from_slice(&key[addr_start..addr_start + 32]);
            }
            addresses.push(addr);
            coins.push(coin);

            if !iter.next() {
                break;
            }
        }

        Ok((frame_numbers, addresses, coins))
    }

    fn get_coin_by_address(&self, address: &[u8]) -> Result<(u64, node::Coin)> {
        let key = encoding::coin_key(address);
        let value = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("coin not found".into()))?;

        if value.len() < 8 {
            return Err(QuilError::Store(
                "coin value too short for frame number".into(),
            ));
        }
        let frame_number = u64::from_be_bytes(value[..8].try_into().unwrap());
        let coin = node::Coin::decode(&value[8..])
            .map_err(|e| QuilError::Serialization(e.to_string()))?;

        Ok((frame_number, coin))
    }

    fn put_coin(
        &self,
        txn: &dyn store::Transaction,
        frame_number: u64,
        address: &[u8],
        coin: &node::Coin,
    ) -> Result<()> {
        let coin_bytes = coin.encode_to_vec();

        let mut data = Vec::with_capacity(8 + coin_bytes.len());
        data.extend_from_slice(&frame_number.to_be_bytes());
        data.extend_from_slice(&coin_bytes);

        let owner_addr = Self::owner_address(coin);
        txn.set(
            &encoding::coin_by_owner_key(owner_addr, address),
            &data,
        )?;
        txn.set(&encoding::coin_key(address), &data)?;

        Ok(())
    }

    fn delete_coin(
        &self,
        txn: &dyn store::Transaction,
        address: &[u8],
        coin: &node::Coin,
    ) -> Result<()> {
        txn.delete(&encoding::coin_key(address))?;

        let owner_addr = Self::owner_address(coin);
        txn.delete(&encoding::coin_by_owner_key(owner_addr, address))?;

        Ok(())
    }

    // -----------------------------------------------------------------
    // Materialized transactions
    // -----------------------------------------------------------------

    fn get_transactions_for_owner(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> Result<Vec<node::MaterializedTransaction>> {
        let lower = encoding::transaction_by_owner_key(domain, owner, &[0x00; 32]);
        let upper = encoding::transaction_by_owner_key(domain, owner, &[0xff; 32]);
        let mut iter = self.make_iter(&lower, &upper);

        let mut transactions = Vec::new();

        if !iter.first() {
            return Ok(transactions);
        }

        loop {
            let txn = node::MaterializedTransaction::decode(iter.value())
                .map_err(|e| QuilError::Serialization(e.to_string()))?;
            transactions.push(txn);

            if !iter.next() {
                break;
            }
        }

        Ok(transactions)
    }

    fn get_transaction_by_address(
        &self,
        domain: &[u8],
        address: &[u8],
    ) -> Result<node::MaterializedTransaction> {
        let key = encoding::transaction_key(domain, address);
        let value = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("transaction not found".into()))?;

        node::MaterializedTransaction::decode(value.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }

    fn put_transaction(
        &self,
        txn: &dyn store::Transaction,
        domain: &[u8],
        owner: &[u8],
        transaction: &node::MaterializedTransaction,
    ) -> Result<()> {
        let txn_bytes = transaction.encode_to_vec();

        txn.set(
            &encoding::transaction_by_owner_key(domain, owner, &transaction.address),
            &txn_bytes,
        )?;
        txn.set(
            &encoding::transaction_key(domain, &transaction.address),
            &txn_bytes,
        )?;

        Ok(())
    }

    fn delete_transaction(
        &self,
        txn: &dyn store::Transaction,
        domain: &[u8],
        address: &[u8],
        owner: &[u8],
    ) -> Result<()> {
        txn.delete(&encoding::transaction_key(domain, address))?;
        txn.delete(&encoding::transaction_by_owner_key(domain, owner, address))?;

        Ok(())
    }

    // -----------------------------------------------------------------
    // Pending transactions
    // -----------------------------------------------------------------

    fn get_pending_transactions_for_owner(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> Result<Vec<node::MaterializedPendingTransaction>> {
        let lower = encoding::pending_transaction_by_owner_key(domain, owner, &[0x00; 32]);
        let upper = encoding::pending_transaction_by_owner_key(domain, owner, &[0xff; 32]);
        let mut iter = self.make_iter(&lower, &upper);

        let mut pending = Vec::new();

        if !iter.first() {
            return Ok(pending);
        }

        loop {
            let ptxn = node::MaterializedPendingTransaction::decode(iter.value())
                .map_err(|e| QuilError::Serialization(e.to_string()))?;
            pending.push(ptxn);

            if !iter.next() {
                break;
            }
        }

        Ok(pending)
    }

    fn get_pending_transaction_by_address(
        &self,
        domain: &[u8],
        address: &[u8],
    ) -> Result<node::MaterializedPendingTransaction> {
        let key = encoding::pending_transaction_key(domain, address);
        let value = self
            .db
            .get(&key)
            .map_err(|e| QuilError::Store(e.to_string()))?
            .ok_or_else(|| QuilError::NotFound("pending transaction not found".into()))?;

        node::MaterializedPendingTransaction::decode(value.as_slice())
            .map_err(|e| QuilError::Serialization(e.to_string()))
    }

    fn put_pending_transaction(
        &self,
        txn: &dyn store::Transaction,
        domain: &[u8],
        owner: &[u8],
        pending: &node::MaterializedPendingTransaction,
    ) -> Result<()> {
        let ptxn_bytes = pending.encode_to_vec();

        txn.set(
            &encoding::pending_transaction_by_owner_key(domain, owner, &pending.address),
            &ptxn_bytes,
        )?;
        txn.set(
            &encoding::pending_transaction_key(domain, &pending.address),
            &ptxn_bytes,
        )?;

        Ok(())
    }

    fn delete_pending_transaction(
        &self,
        txn: &dyn store::Transaction,
        domain: &[u8],
        owner: &[u8],
        pending: &node::MaterializedPendingTransaction,
    ) -> Result<()> {
        txn.delete(&encoding::pending_transaction_key(domain, &pending.address))?;
        txn.delete(&encoding::pending_transaction_by_owner_key(
            domain,
            owner,
            &pending.address,
        ))?;

        Ok(())
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::node::{
        account_ref, AccountRef, Coin, ImplicitAccount, MaterializedPendingTransaction,
        MaterializedTransaction,
    };
    use quil_types::store::TokenStore;

    fn open_test_store() -> RocksTokenStore {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, tmp.path()).unwrap();
        // Leak the TempDir so it lives as long as the DB handle.
        std::mem::forget(tmp);
        RocksTokenStore::new(Arc::new(db))
    }

    fn make_coin(amount: &[u8], owner_addr: &[u8]) -> Coin {
        Coin {
            amount: amount.to_vec(),
            intersection: vec![],
            owner: Some(AccountRef {
                account: Some(account_ref::Account::ImplicitAccount(ImplicitAccount {
                    implicit_type: 0,
                    address: owner_addr.to_vec(),
                    domain: vec![],
                })),
            }),
        }
    }

    // -----------------------------------------------------------------
    // Coin tests
    // -----------------------------------------------------------------

    #[test]
    fn test_put_get_coin_by_address() {
        let store = open_test_store();
        let owner = [0xAA; 32];
        let addr = [0xBB; 32];
        let coin = make_coin(&[0x01, 0x00], &owner);

        let txn = store.new_transaction(false).unwrap();
        store.put_coin(txn.as_ref(), 42, &addr, &coin).unwrap();
        txn.commit().unwrap();

        let (frame, got) = store.get_coin_by_address(&addr).unwrap();
        assert_eq!(frame, 42);
        assert_eq!(got.amount, coin.amount);
        assert_eq!(
            RocksTokenStore::owner_address(&got),
            &owner[..],
        );
    }

    #[test]
    fn test_get_coin_not_found() {
        let store = open_test_store();
        let result = store.get_coin_by_address(&[0xFF; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            QuilError::NotFound(_) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_get_coins_for_owner() {
        let store = open_test_store();
        let owner = [0xAA; 32];

        let addr1 = [0x11; 32];
        let addr2 = [0x22; 32];
        let coin1 = make_coin(&[0x0A], &owner);
        let coin2 = make_coin(&[0x0B], &owner);

        let txn = store.new_transaction(false).unwrap();
        store.put_coin(txn.as_ref(), 10, &addr1, &coin1).unwrap();
        store.put_coin(txn.as_ref(), 20, &addr2, &coin2).unwrap();
        txn.commit().unwrap();

        let (frames, addrs, coins) = store.get_coins_for_owner(&owner).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(addrs.len(), 2);
        assert_eq!(coins.len(), 2);

        // RocksDB iterates in key order; addr1 (0x11...) < addr2 (0x22...)
        assert_eq!(frames[0], 10);
        assert_eq!(frames[1], 20);
        assert_eq!(addrs[0], addr1.to_vec());
        assert_eq!(addrs[1], addr2.to_vec());
        assert_eq!(coins[0].amount, vec![0x0A]);
        assert_eq!(coins[1].amount, vec![0x0B]);
    }

    #[test]
    fn test_get_coins_for_owner_empty() {
        let store = open_test_store();
        let (frames, addrs, coins) = store.get_coins_for_owner(&[0xFF; 32]).unwrap();
        assert!(frames.is_empty());
        assert!(addrs.is_empty());
        assert!(coins.is_empty());
    }

    #[test]
    fn test_delete_coin() {
        let store = open_test_store();
        let owner = [0xAA; 32];
        let addr = [0xBB; 32];
        let coin = make_coin(&[0x01], &owner);

        // Put
        let txn = store.new_transaction(false).unwrap();
        store.put_coin(txn.as_ref(), 5, &addr, &coin).unwrap();
        txn.commit().unwrap();

        // Verify exists
        assert!(store.get_coin_by_address(&addr).is_ok());

        // Delete
        let txn = store.new_transaction(false).unwrap();
        store.delete_coin(txn.as_ref(), &addr, &coin).unwrap();
        txn.commit().unwrap();

        // Verify gone from both indexes
        assert!(store.get_coin_by_address(&addr).is_err());
        let (frames, _, _) = store.get_coins_for_owner(&owner).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn test_coins_isolated_by_owner() {
        let store = open_test_store();

        let owner_a = [0xAA; 32];
        let owner_b = [0xBB; 32];
        let addr_a = [0x11; 32];
        let addr_b = [0x22; 32];

        let txn = store.new_transaction(false).unwrap();
        store
            .put_coin(txn.as_ref(), 1, &addr_a, &make_coin(&[1], &owner_a))
            .unwrap();
        store
            .put_coin(txn.as_ref(), 2, &addr_b, &make_coin(&[2], &owner_b))
            .unwrap();
        txn.commit().unwrap();

        let (frames_a, _, _) = store.get_coins_for_owner(&owner_a).unwrap();
        assert_eq!(frames_a.len(), 1);
        assert_eq!(frames_a[0], 1);

        let (frames_b, _, _) = store.get_coins_for_owner(&owner_b).unwrap();
        assert_eq!(frames_b.len(), 1);
        assert_eq!(frames_b[0], 2);
    }

    // -----------------------------------------------------------------
    // Transaction tests
    // -----------------------------------------------------------------

    #[test]
    fn test_put_get_transaction() {
        let store = open_test_store();
        let domain = [0xDD; 32];
        let owner = [0xAA; 32];
        let mt = MaterializedTransaction {
            address: vec![0x11; 32],
            raw_balance: vec![0x00, 0x64],
            frame_number: 100,
            commitment: vec![0xCC; 32],
            one_time_key: vec![],
            verification_key: vec![],
            coin_balance: vec![],
            mask: vec![],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        let txn = store.new_transaction(false).unwrap();
        store
            .put_transaction(txn.as_ref(), &domain, &owner, &mt)
            .unwrap();
        txn.commit().unwrap();

        // By address
        let got = store
            .get_transaction_by_address(&domain, &mt.address)
            .unwrap();
        assert_eq!(got.frame_number, 100);
        assert_eq!(got.raw_balance, mt.raw_balance);

        // By owner
        let txns = store.get_transactions_for_owner(&domain, &owner).unwrap();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].address, mt.address);
    }

    #[test]
    fn test_delete_transaction() {
        let store = open_test_store();
        let domain = [0xDD; 32];
        let owner = [0xAA; 32];
        let addr = [0x11; 32];

        let mt = MaterializedTransaction {
            address: addr.to_vec(),
            raw_balance: vec![],
            frame_number: 50,
            commitment: vec![],
            one_time_key: vec![],
            verification_key: vec![],
            coin_balance: vec![],
            mask: vec![],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        let txn = store.new_transaction(false).unwrap();
        store
            .put_transaction(txn.as_ref(), &domain, &owner, &mt)
            .unwrap();
        txn.commit().unwrap();

        let txn = store.new_transaction(false).unwrap();
        store
            .delete_transaction(txn.as_ref(), &domain, &addr, &owner)
            .unwrap();
        txn.commit().unwrap();

        assert!(store.get_transaction_by_address(&domain, &addr).is_err());
        let txns = store.get_transactions_for_owner(&domain, &owner).unwrap();
        assert!(txns.is_empty());
    }

    // -----------------------------------------------------------------
    // Pending transaction tests
    // -----------------------------------------------------------------

    #[test]
    fn test_put_get_pending_transaction() {
        let store = open_test_store();
        let domain = [0xDD; 32];
        let owner = [0xAA; 32];
        let pt = MaterializedPendingTransaction {
            address: vec![0x33; 32],
            raw_balance: vec![0x00, 0xC8],
            frame_number: 200,
            commitment: vec![],
            to_one_time_key: vec![],
            refund_one_time_key: vec![],
            to_verification_key: vec![],
            refund_verification_key: vec![],
            to_coin_balance: vec![],
            refund_coin_balance: vec![],
            to_mask: vec![],
            refund_mask: vec![],
            to_additional_reference: vec![],
            to_additional_reference_key: vec![],
            refund_additional_reference: vec![],
            refund_additional_reference_key: vec![],
            expiration: 999,
        };

        let txn = store.new_transaction(false).unwrap();
        store
            .put_pending_transaction(txn.as_ref(), &domain, &owner, &pt)
            .unwrap();
        txn.commit().unwrap();

        // By address
        let got = store
            .get_pending_transaction_by_address(&domain, &pt.address)
            .unwrap();
        assert_eq!(got.frame_number, 200);
        assert_eq!(got.expiration, 999);

        // By owner
        let pts = store
            .get_pending_transactions_for_owner(&domain, &owner)
            .unwrap();
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].address, pt.address);
    }

    #[test]
    fn test_delete_pending_transaction() {
        let store = open_test_store();
        let domain = [0xDD; 32];
        let owner = [0xAA; 32];
        let pt = MaterializedPendingTransaction {
            address: vec![0x33; 32],
            raw_balance: vec![],
            frame_number: 0,
            commitment: vec![],
            to_one_time_key: vec![],
            refund_one_time_key: vec![],
            to_verification_key: vec![],
            refund_verification_key: vec![],
            to_coin_balance: vec![],
            refund_coin_balance: vec![],
            to_mask: vec![],
            refund_mask: vec![],
            to_additional_reference: vec![],
            to_additional_reference_key: vec![],
            refund_additional_reference: vec![],
            refund_additional_reference_key: vec![],
            expiration: 0,
        };

        let txn = store.new_transaction(false).unwrap();
        store
            .put_pending_transaction(txn.as_ref(), &domain, &owner, &pt)
            .unwrap();
        txn.commit().unwrap();

        let txn = store.new_transaction(false).unwrap();
        store
            .delete_pending_transaction(txn.as_ref(), &domain, &owner, &pt)
            .unwrap();
        txn.commit().unwrap();

        assert!(store
            .get_pending_transaction_by_address(&domain, &pt.address)
            .is_err());
        let pts = store
            .get_pending_transactions_for_owner(&domain, &owner)
            .unwrap();
        assert!(pts.is_empty());
    }

    #[test]
    fn test_multiple_transactions_for_owner() {
        let store = open_test_store();
        let domain = [0xDD; 32];
        let owner = [0xAA; 32];

        let txn = store.new_transaction(false).unwrap();
        for i in 0u8..5 {
            let mt = MaterializedTransaction {
                address: vec![i; 32],
                raw_balance: vec![i],
                frame_number: i as u64,
                commitment: vec![],
                one_time_key: vec![],
                verification_key: vec![],
                coin_balance: vec![],
                mask: vec![],
                additional_reference: vec![],
                additional_reference_key: vec![],
            };
            store
                .put_transaction(txn.as_ref(), &domain, &owner, &mt)
                .unwrap();
        }
        txn.commit().unwrap();

        let txns = store.get_transactions_for_owner(&domain, &owner).unwrap();
        assert_eq!(txns.len(), 5);
        for (i, t) in txns.iter().enumerate() {
            assert_eq!(t.frame_number, i as u64);
        }
    }

    #[test]
    fn test_key_encoding_matches_go() {
        // Verify our key encodings produce the expected byte layout.
        let addr = [0xAB; 32];
        let key = encoding::coin_key(&addr);
        assert_eq!(key[0], 0x07); // COIN
        assert_eq!(key[1], 0x00); // COIN_BY_ADDRESS
        assert_eq!(&key[2..], &addr[..]);

        let owner = [0xCD; 32];
        let key = encoding::coin_by_owner_key(&owner, &addr);
        assert_eq!(key[0], 0x07);
        assert_eq!(key[1], 0x01); // COIN_BY_OWNER
        assert_eq!(&key[2..34], &owner[..]);
        assert_eq!(&key[34..], &addr[..]);

        let domain = [0xEE; 32];
        let key = encoding::transaction_key(&domain, &addr);
        assert_eq!(key[0], 0x07);
        assert_eq!(key[1], 0x02); // TRANSACTION_BY_ADDRESS

        let key = encoding::transaction_by_owner_key(&domain, &owner, &addr);
        assert_eq!(key[0], 0x07);
        assert_eq!(key[1], 0x03); // TRANSACTION_BY_OWNER

        let key = encoding::pending_transaction_key(&domain, &addr);
        assert_eq!(key[0], 0x07);
        assert_eq!(key[1], 0x04); // PENDING_TRANSACTION_BY_ADDRESS

        let key = encoding::pending_transaction_by_owner_key(&domain, &owner, &addr);
        assert_eq!(key[0], 0x07);
        assert_eq!(key[1], 0x05); // PENDING_TRANSACTION_BY_OWNER
    }
}
