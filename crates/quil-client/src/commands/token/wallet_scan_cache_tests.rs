//! The scan cache: coins found not ours are skipped by later scans, and
//! nothing about the cache can hide an owned coin or fail a scan.
use super::super::scan_cache::{read_entries, Entry, ScanCache, MAX_ENTRIES};
use super::*;
use quil_lattice_ct::confidential::{memo::create_output, transfer::MEMO_BYTES};

const NETWORK: [u8; 32] = [41; 32];
const APPLICATION: [u8; 32] = quil_execution::domains::QUIL_TOKEN;

fn wallet() -> RecipientWallet {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    RecipientWallet::from_keys(
        &NETWORK,
        &APPLICATION,
        &keys.public,
        Zeroizing::new(keys.secret),
    )
    .unwrap()
}

fn address(index: usize) -> [u8; 32] {
    let mut address = [7; 32];
    address[..8].copy_from_slice(&(index as u64).to_be_bytes());
    address
}

/// `others` coins to someone else, then `owned` coins of amounts 5, 6, ...
/// to `ours`, all at distinct addresses.
fn page(ours: &RecipientWallet, others: usize, owned: usize) -> Vec<([u8; 32], Output)> {
    let stranger = wallet();
    (0..others)
        .map(|i| (stranger.address(), 1 + i as u128))
        .chain((0..owned).map(|i| (ours.address(), 5 + i as u128)))
        .enumerate()
        .map(|(i, (to, amount))| {
            let output = create_output(&ours.context, to, amount).unwrap().output;
            (address(i), output)
        })
        .collect()
}

fn cache(wallet: &RecipientWallet, dir: &std::path::Path) -> ScanCache {
    ScanCache::load(dir, &wallet.context, &wallet.kem_secret)
}

fn amounts(recovery: &PageRecovery) -> Vec<u128> {
    let mut amounts: Vec<_> = recovery.owned.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    amounts
}

#[test]
fn scan_cache_skips_coins_found_not_ours_and_reopens_owned_ones() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 6, 2);
    let cold = ours
        .recover_page_with(coins.clone(), Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    assert_eq!((cold.opened, cold.not_ours.len()), (8, 6));
    assert_eq!(amounts(&cold), [5, 6]);
    cache(&ours, dir.path()).store(cold.not_ours, true);
    // One thread and several: only the two owned coins are opened again.
    for threads in [1, 4] {
        let warm = ours
            .recover_page_with(coins.clone(), Some(&cache(&ours, dir.path())), threads)
            .unwrap();
        assert_eq!(warm.opened, 2, "cached coins must not be opened");
        assert_eq!(warm.not_ours.len(), 6);
        assert_eq!(amounts(&warm), [5, 6], "owned coins are always opened");
    }
}

#[test]
fn scan_cache_never_stores_an_owned_coin() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 3, 2);
    let cache = cache(&ours, dir.path());
    let cold = ours
        .recover_page_with(coins.clone(), Some(&cache), 1)
        .unwrap();
    cache.store(cold.not_ours, true);
    let stored = read_entries(cache.path(), MAX_ENTRIES).unwrap();
    assert_eq!(stored.len(), 3);
    for (address, output) in &coins[3..] {
        assert!(!stored.contains(&cache.entry(address, output)));
    }
}

#[test]
fn scan_cache_misses_a_changed_output_or_address() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 4, 0);
    let first = ours
        .recover_page_with(coins.clone(), Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    cache(&ours, dir.path()).store(first.not_ours, true);
    // The same address with another coin's output, a flipped memo byte, an
    // unchanged output at a new address, and one coin unchanged.
    let mut changed = coins.clone();
    changed[0].1 = coins[1].1.clone();
    changed[1].1.memo[MEMO_BYTES - 1] ^= 1;
    changed[2].0 = address(99);
    let again = ours
        .recover_page_with(changed, Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    assert_eq!(again.opened, 3, "only the unchanged coin may hit");
}

#[test]
fn scan_cache_entries_of_another_key_never_match() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 4, 0);
    let first = ours
        .recover_page_with(coins.clone(), Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    cache(&ours, dir.path()).store(first.not_ours, true);
    // Another key in the same config directory and application reads the
    // same file and must open every coin itself.
    let other = wallet();
    let theirs = other
        .recover_page_with(coins, Some(&cache(&other, dir.path())), 1)
        .unwrap();
    assert_eq!(theirs.opened, 4);
}

#[test]
fn scan_cache_keeps_each_swapped_key_warm() {
    // An operator swaps two keys in one config directory: each key's cache
    // survives the other's scans, so swapping back opens nothing again.
    let dir = tempfile::tempdir().unwrap();
    let (first, second) = (wallet(), wallet());
    let coins = page(&first, 5, 0);
    for wallet in [&first, &second] {
        let cold = wallet
            .recover_page_with(coins.clone(), Some(&cache(wallet, dir.path())), 1)
            .unwrap();
        assert_eq!(cold.opened, 5);
        cache(wallet, dir.path()).store(cold.not_ours, true);
    }
    assert_ne!(
        cache(&first, dir.path()).path(),
        cache(&second, dir.path()).path()
    );
    for wallet in [&first, &second] {
        let warm = wallet
            .recover_page_with(coins.clone(), Some(&cache(wallet, dir.path())), 1)
            .unwrap();
        assert_eq!(warm.opened, 0);
    }
}

#[test]
fn scan_cache_complete_scans_prune_and_incomplete_ones_merge() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let entry = |n: u8| -> Entry { [n; 32] };
    cache(&ours, dir.path()).store(vec![entry(3), entry(1), entry(2)], true);
    let path = cache(&ours, dir.path()).path().to_path_buf();
    assert_eq!(
        read_entries(&path, MAX_ENTRIES).unwrap(),
        [entry(1), entry(2), entry(3)]
    );
    // A complete scan that saw only one of them: the rest left the unspent set.
    cache(&ours, dir.path()).store(vec![entry(2)], true);
    assert_eq!(read_entries(&path, MAX_ENTRIES).unwrap(), [entry(2)]);
    // An incomplete scan cannot tell: it only adds.
    cache(&ours, dir.path()).store(vec![entry(4)], false);
    assert_eq!(
        read_entries(&path, MAX_ENTRIES).unwrap(),
        [entry(2), entry(4)]
    );
}

#[test]
fn scan_cache_is_capped_and_coins_past_the_cap_are_opened() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 10, 1);
    let cold = ours
        .recover_page_with(coins.clone(), Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    cache(&ours, dir.path()).store_capped(cold.not_ours, true, 4);
    let path = cache(&ours, dir.path()).path().to_path_buf();
    assert_eq!(read_entries(&path, MAX_ENTRIES).unwrap().len(), 4);
    // A file over the cap a reader allows is ignored whole.
    assert!(read_entries(&path, 3).is_none());
    let warm = ours
        .recover_page_with(coins, Some(&cache(&ours, dir.path())), 1)
        .unwrap();
    assert_eq!((warm.opened, amounts(&warm)), (7, vec![5]));
}

#[test]
fn scan_cache_ignores_corrupt_files_and_rebuilds_them() {
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    let coins = page(&ours, 3, 1);
    let path = cache(&ours, dir.path()).path().to_path_buf();
    let file = |entries: &[Entry], count: u64| {
        let mut bytes = b"QCSCAN\0\0".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        entries
            .iter()
            .for_each(|entry| bytes.extend_from_slice(entry));
        bytes
    };
    let entries: Vec<Entry> = {
        let probe = cache(&ours, dir.path());
        let mut entries: Vec<_> = coins[..3]
            .iter()
            .map(|(address, output)| probe.entry(address, output))
            .collect();
        entries.sort();
        entries
    };
    // A well-formed file of these entries is used...
    std::fs::write(&path, file(&entries, 3)).unwrap();
    assert_eq!(read_entries(&path, MAX_ENTRIES).unwrap(), entries);
    // ...and every damaged form of it is ignored, then rebuilt.
    let mut wrong_version = file(&entries, 3);
    wrong_version[8] = 2;
    let mut unsorted = entries.clone();
    unsorted.swap(0, 2);
    let mut trailing = file(&entries[..2], 2);
    trailing.extend_from_slice(&entries[2]);
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("garbage", vec![0x5a; 100]),
        ("truncated", file(&entries, 3)[..50].to_vec()),
        ("count beyond the data", file(&entries, 4)),
        ("an entry past the count", trailing),
        ("wrong version", wrong_version),
        ("unsorted", file(&unsorted, 3)),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_entries(&path, MAX_ENTRIES).is_none(), "{name}");
        let cache = cache(&ours, dir.path());
        let recovered = ours
            .recover_page_with(coins.clone(), Some(&cache), 1)
            .unwrap();
        assert_eq!(
            (recovered.opened, amounts(&recovered)),
            (4, vec![5]),
            "{name}"
        );
        cache.store(recovered.not_ours, true);
        assert_eq!(
            read_entries(&path, MAX_ENTRIES).unwrap(),
            entries,
            "{name} is rebuilt"
        );
    }
}

#[cfg(unix)]
#[test]
fn scan_cache_file_is_private_and_replaced_whole() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ours = wallet();
    cache(&ours, dir.path()).store(vec![[1; 32]], true);
    cache(&ours, dir.path()).store(vec![[2; 32]], true);
    let path = cache(&ours, dir.path()).path().to_path_buf();
    assert_eq!(read_entries(&path, MAX_ENTRIES).unwrap(), [[2; 32]]);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [path.file_name().unwrap().to_owned()],
        "no temporary file left"
    );
}

/// Cold and warm scans over synthetic pages of 64, timed. Run alone on a
/// quiet host: `--run-ignored only --no-capture -E 'test(scan_cache_timing)'`.
/// `SCAN_CACHE_TIMING_COINS` sets the not-ours coin count (default 2,000).
#[test]
#[ignore]
fn scan_cache_timing() {
    let others = std::env::var("SCAN_CACHE_TIMING_COINS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2000);
    let ours = wallet();
    let coins = page(&ours, others, 2);
    let pages: Vec<_> = coins.chunks(64).map(<[_]>::to_vec).collect();
    let run = |label: &str, dir: Option<&std::path::Path>, threads: usize| {
        let started = std::time::Instant::now();
        let cache = dir.map(|dir| cache(&ours, dir));
        let (mut opened, mut owned, mut not_ours) = (0, 0, Vec::new());
        for page in &pages {
            let recovery = ours
                .recover_page_with(page.clone(), cache.as_ref(), threads)
                .unwrap();
            opened += recovery.opened;
            owned += recovery.owned.len();
            not_ours.extend(recovery.not_ours);
        }
        if let Some(cache) = &cache {
            cache.store(not_ours, true);
        }
        let elapsed = started.elapsed();
        assert_eq!(owned, 2);
        println!(
            "scan_cache_timing {label}: coins={} threads={threads} opened={opened} ms={} us_per_coin={:.1}",
            coins.len(),
            elapsed.as_millis(),
            elapsed.as_micros() as f64 / coins.len() as f64
        );
    };
    let threads = open_threads();
    run("no cache", None, 1);
    let single = tempfile::tempdir().unwrap();
    run("cold", Some(single.path()), 1);
    run("warm", Some(single.path()), 1);
    let parallel = tempfile::tempdir().unwrap();
    run("cold", Some(parallel.path()), threads);
    run("warm", Some(parallel.path()), threads);
}
