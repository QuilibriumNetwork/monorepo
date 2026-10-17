//! Complete transfer fixture with real recipient memos. Fixed input
//! seeds are public benchmark data. This does not exercise node admission.
use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use quil_lattice_ct::confidential::{
    address::RecipientAddress,
    coin_tree::{CoinRecord, CoinTree, RootRecord, ROOT_RECORD_BYTES},
    memo::{create_output, open_output},
    relation::{
        backend::native::{self, NativeBudget},
        membership::{InputPath, MembershipKey, Node, NoteSecrets, RecipientSecret},
    },
    transfer::{
        CompileLimits, Transfer, TransferStatement, MAX_TRANSACTION_BYTES, TARGET_TRANSACTION_BYTES,
    },
    CommitmentKey,
};
use std::{io::Read, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 4 || args.len() == 6,
        "usage: transfer_roundtrip prove|verify|verify-binding DEPTH TRANSACTION_PATH NATIVE_MIB [EXPECTED_NETWORK_HEX EXPECTED_APPLICATION_HEX]"
    );
    assert!(matches!(
        args[0].as_str(),
        "prove" | "verify" | "verify-binding"
    ));
    assert!(args.len() == 4 || args[0] != "prove", "explicit domains are for saved-fixture verification");
    let parse_domain = |value: &str| -> [u8; 32] {
        assert!(value.len() == 64 && value.is_ascii(), "expected 32-byte hex domain");
        std::array::from_fn(|i| u8::from_str_radix(&value[2*i..2*i+2], 16).expect("hex domain"))
    };
    // Expected domains are supplied by the benchmark caller, never inferred
    // from the unverified transaction. Existing example fixtures keep defaults.
    let (network, application) = if args.len() == 6 {
        (parse_domain(&args[4]), parse_domain(&args[5]))
    } else {
        ([1; 32], [2; 32])
    };
    let depth: usize = args[1].parse().expect("numeric depth");
    assert!([1, 8, 16, 32].contains(&depth));
    let limits = CompileLimits {
        max_inputs: 2,
        max_outputs: 2,
        max_depth: depth,
    };
    let budget = NativeBudget {
        max_native_bytes: args[3]
            .parse::<usize>()
            .expect("numeric native MiB")
            .checked_mul(1 << 20)
            .expect("bounded native MiB"),
    };
    let start = Instant::now();
    if args[0] != "prove" {
        let mut bytes = Vec::new();
        std::fs::File::open(&args[2])
            .expect("open transaction")
            .take(MAX_TRANSACTION_BYTES as u64)
            .read_to_end(&mut bytes)
            .expect("read bounded transaction");
        let tx = Transfer::decode(&bytes, &network, &application)
            .expect("canonical transaction in expected domains");
        assert_eq!(usize::from(tx.statement.depth), depth);
        // A separately saved fixture root models an admitted snapshot. Never
        // treat a root declared by the incoming transaction as admitted state.
        let mut root_bytes = Vec::new();
        std::fs::File::open(format!("{}.root", args[2]))
            .expect("open fixture snapshot root")
            .take((ROOT_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut root_bytes)
            .expect("read bounded root record");
        let root = RootRecord::decode(&root_bytes, &tx.statement.parameter_context())
            .expect("canonical fixture root");
        assert_eq!(root.depth, tx.statement.depth);
        assert_eq!(
            root.root, tx.statement.root,
            "transaction root must match fixture snapshot"
        );
        let public = tx
            .statement
            .public_relation(limits)
            .expect("independent public relation");
        assert!(native::verify_owned(public, &tx.proof, budget).expect("native verification"));
        println!("transfer_public_verification depth={depth} bytes={} proof_bytes={} valid=true seconds={:.3}", bytes.len(), tx.proof.len(), start.elapsed().as_secs_f64());
        assert!(
            bytes.len() <= TARGET_TRANSACTION_BYTES,
            "transaction exceeds 256 KiB target"
        );
        if args[0] == "verify-binding" {
            // First require acceptance of the original fixture above. Errors,
            // allocation failures and invalid fixtures cannot count as rejection.
            for field in ["memo", "owner"] {
                let check_start = Instant::now();
                let mut changed = tx.clone();
                match field {
                    "memo" => changed.statement.outputs[0].memo[0] ^= 1,
                    "owner" => changed.statement.outputs[0].owner[0] ^= 1,
                    _ => unreachable!(),
                }
                let encoded = changed.encode().expect("mutation remains canonical");
                let changed = Transfer::decode(&encoded, &network, &application)
                    .expect("mutation roundtrips through wire decoder");
                assert_ne!(
                    changed.statement.context_bytes().unwrap(),
                    tx.statement.context_bytes().unwrap()
                );
                assert_eq!(changed.proof, tx.proof);
                let public = changed
                    .statement
                    .public_relation(limits)
                    .expect("mutated public relation");
                let accepted = native::verify_owned(public, &changed.proof, budget)
                    .expect("native rejection check must complete without a backend error");
                assert!(!accepted, "proof accepted changed {field}");
                println!("transfer_binding depth={depth} field={field} rejected=true seconds={:.3}", check_start.elapsed().as_secs_f64());
            }
        }
        return;
    }
    let mut statement = TransferStatement {
        network: [1; 32],
        application: [2; 32],
        depth: depth as u8,
        root: Node::zero(),
        images: Vec::new(),
        outputs: Vec::new(),
        fee: 2,
    };
    let context = statement.parameter_context();
    let key = CommitmentKey::derive(&context);
    let membership = MembershipKey::derive(&context);
    let input_recipient = RecipientSecret::from_seed(&context, &[99; 32]);
    let notes: [_; 2] = std::array::from_fn(|i| {
        NoteSecrets::from_seeds(&context, &input_recipient, &[10 + i as u8; 32])
    });
    let amounts = [u128::MAX, 257];
    let commitments: [_; 2] = std::array::from_fn(|i| key.commit(amounts[i], &notes[i].opening));
    let coins: [_; 2] = std::array::from_fn(|i| (amounts[i], &notes[i].opening, &commitments[i]));
    statement.images = notes
        .iter()
        .map(|n| membership.key_image(&n.owner).identity_bytes().unwrap())
        .collect();
    let records: Vec<_> = (0..2)
        .map(|i| CoinRecord {
            address: [i as u8; 32],
            owner: membership
                .owner_key(&notes[i].owner)
                .identity_bytes()
                .unwrap(),
            commitment: commitments[i].clone(),
            position: i as u64,
        })
        .collect();
    let tree =
        CoinTree::build(&context, &records, 32, 64).expect("bounded canonical coin snapshot");
    let root_record = tree.root_at_depth(depth).expect("configured snapshot root");
    statement.root = root_record.root.clone();
    let auth: Vec<_> = records
        .iter()
        .map(|coin| tree.auth_path(&coin.address, depth).unwrap())
        .collect();
    let paths: [_; 2] = std::array::from_fn(|i| InputPath {
        owner: &notes[i].owner,
        siblings: &auth[i].siblings,
        right: &auth[i].right,
    });
    let output_amounts = [u128::MAX - 1, 256];
    let mut openings = Vec::new();
    for (i, &amount) in output_amounts.iter().enumerate() {
        let recipient = RecipientSecret::from_seed(&context, &[110 + i as u8; 32]);
        let (public, secret) = sntrup761::keypair();
        let address = RecipientAddress::new(&context, &recipient, public.as_bytes())
            .expect("recipient address");
        let address = RecipientAddress::decode(&address.encode(), &context)
            .expect("sender checks address context");
        let created = create_output(&context, &address, amount).expect("real recipient memo");
        let opened = open_output(&context, secret.as_bytes(), &recipient, &created.output)
            .expect("recipient recovers and validates note");
        assert_eq!(opened.amount, amount);
        assert_eq!(
            membership
                .owner_key(&opened.secrets.owner)
                .identity_bytes()
                .unwrap(),
            created.output.owner
        );
        statement.outputs.push(created.output);
        openings.push(created.opening);
    }
    let output_witness: Vec<_> = output_amounts
        .iter()
        .zip(&openings)
        .map(|(&v, r)| (v, r))
        .collect();
    let relation = statement
        .private_relation(&coins, &output_witness, &paths, limits)
        .expect("complete private transfer relation");
    eprintln!(
        "transfer_loaded depth={depth} recipient_memos_verified=2 seconds={:.3}",
        start.elapsed().as_secs_f64()
    );
    let proof = native::prove(&relation, budget).expect("complete transfer proof");
    let tx = Transfer { statement, proof };
    let bytes = tx.encode().expect("bounded canonical complete transfer");
    assert_eq!(Transfer::decode(&bytes, &[1; 32], &[2; 32]).unwrap(), tx);
    std::fs::write(format!("{}.root", args[2]), root_record.encode().unwrap())
        .expect("write fixture root record");
    std::fs::write(&args[2], &bytes).expect("write transaction");
    println!("transfer_proved depth={depth} bytes={} proof_bytes={} recipient_memos_verified=2 seconds={:.3}", bytes.len(), tx.proof.len(), start.elapsed().as_secs_f64());
    assert!(
        bytes.len() <= TARGET_TRANSACTION_BYTES,
        "transaction exceeds 256 KiB target"
    );
}
