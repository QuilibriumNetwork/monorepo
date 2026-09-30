//! Fixed public-fixture compiler benchmark and opt-in native proof roundtrip.
//! All seeds here are public test data; never use them for real coins.
use quil_lattice_ct::confidential::{
    relation::{
        membership::{
            InputPath, MembershipKey, MembershipStatement, Node, NoteSecrets, RecipientSecret, IDENTITY_BYTES, NODE_BYTES,
        },
        CompiledAmountRelation, PublicAmountRelation,
    },
    CommitmentKey,
};
use std::time::Instant;

#[path = "support/backend_fixture.rs"]
mod backend_fixture;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let export_depth = match args.as_slice() {
        [] => None,
        [flag, depth] if flag == "--emit-backend-fixture" || flag == "--check-portable-fixture" || flag == "--emit-public-backend-fixture" => {
            let depth: usize = depth.parse().expect("numeric depth");
            assert!([1, 8, 16, 32].contains(&depth), "supported fixture depth");
            Some(depth)
        }
        #[cfg(feature = "native-proof")]
        [flag, depth, _, budget, context @ ..] if (flag == "--native-prove" || flag == "--native-verify" || flag == "--native-error") && context.len() <= 1 => {
            let depth: usize = depth.parse().expect("numeric depth");
            assert!([1, 8, 16, 32].contains(&depth), "supported fixture depth");
            budget.parse::<usize>().expect("native allocation budget in MiB");
            Some(depth)
        }
        _ => panic!("usage: amount_relation_profile [--emit-backend-fixture|--emit-public-backend-fixture|--check-portable-fixture 1|8|16|32] or --native-prove|--native-verify DEPTH PROOF_PATH BUDGET_MIB; --native-error DEPTH STAGE BUDGET_MIB [TRANSACTION_CONTEXT] (requires native-proof)"),
    };
    let context = [3; 32];
    let start = Instant::now();
    let value_key = CommitmentKey::derive(&context);
    let key = MembershipKey::derive(&context);
    let setup_seconds = start.elapsed().as_secs_f64();
    let notes: [_; 4] = std::array::from_fn(|i| {
        NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[99; 32]),
            &[i as u8 + 10; 32],
        )
    });
    let amounts = [u128::MAX, 257, u128::MAX - 1, 256];
    let commitments: [_; 4] =
        std::array::from_fn(|i| value_key.commit(amounts[i], &notes[i].opening));
    let coins: [_; 4] = std::array::from_fn(|i| (amounts[i], &notes[i].opening, &commitments[i]));
    let leaves: [_; 2] =
        std::array::from_fn(|i| key.leaf(&key.owner_key(&notes[i].owner), &commitments[i]));
    let images: [_; 2] = std::array::from_fn(|i| key.key_image(&notes[i].owner));
    for depth in export_depth.map_or_else(|| vec![8, 16, 32], |depth| vec![depth]) {
        // Two actual fixture leaves share a subtree; remaining sibling nodes
        // are zero fixtures. This measures valid path constraints, not building
        // or storing an exponentially large tree.
        let mut siblings = [vec![leaves[1].clone()], vec![leaves[0].clone()]];
        let mut directions = [vec![false], vec![true]];
        let mut root = key.parent(&leaves[0], &leaves[1]);
        for level in 1..depth {
            let right = level % 2 == 1;
            root = if right {
                key.parent(&Node::zero(), &root)
            } else {
                key.parent(&root, &Node::zero())
            };
            for i in 0..2 {
                siblings[i].push(Node::zero());
                directions[i].push(right);
            }
        }
        let paths: [_; 2] = std::array::from_fn(|i| InputPath {
            owner: &notes[i].owner,
            siblings: &siblings[i],
            right: &directions[i],
        });
        let statement = MembershipStatement {
            root: &root,
            key_images: &images,
            depth,
        };
        let start = Instant::now();
        let mode = args.first().map(String::as_str);
        if mode == Some("--emit-public-backend-fixture") || mode == Some("--native-verify") {
            let public = PublicAmountRelation::compile_with_membership(
                &value_key,
                &key,
                &commitments[2..],
                0,
                2,
                &statement,
            )
            .expect("public-only fixture compiles");
            #[cfg(feature = "native-proof")]
            if mode == Some("--native-verify") {
                use quil_lattice_ct::confidential::relation::backend::native;
                use std::io::Read;
                let public = match args.get(4) {
                    Some(context) => public.with_transaction_context(context.as_bytes()),
                    None => public,
                };
                let mut proof = Vec::new();
                std::fs::File::open(&args[2])
                    .expect("open proof")
                    .take(native::MAX_PROOF_BYTES as u64)
                    .read_to_end(&mut proof)
                    .expect("read bounded proof");
                assert!(proof.len() < native::MAX_PROOF_BYTES, "proof exceeds bound");
                let valid = native::verify_owned(public, &proof, native_budget(&args[3]))
                    .expect("native public verification");
                println!("native_public_verification depth={depth} proof_bytes={} valid={valid} seconds={:.3} context_bound={}", proof.len(), start.elapsed().as_secs_f64(), args.get(4).is_some());
                assert!(valid, "public verifier rejected fixture proof");
                continue;
            }
            let stdout = std::io::stdout();
            let mut sink = backend_fixture::PublicFixtureSink(backend_fixture::FixtureSink(
                std::io::BufWriter::new(stdout.lock()),
            ));
            public
                .submit(&mut sink)
                .expect("public-only fixture submission");
            continue;
        }
        let relation = CompiledAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &coins[..2],
            &coins[2..],
            0,
            2,
            &statement,
            &paths,
        )
        .expect("public fixture compiles");
        #[cfg(feature = "native-proof")]
        if mode == Some("--native-prove") || mode == Some("--native-error") {
            use quil_lattice_ct::confidential::relation::backend::native;
            let relation = match args.get(4) {
                Some(context) => relation.with_transaction_context(context.as_bytes()),
                None => relation,
            };
            if mode == Some("--native-error") {
                let stage = args[2].parse::<u32>().expect("sampling error stage 1..3");
                native::check_sampling_failure(&relation, native_budget(&args[3]), stage)
                    .expect("sampling failure must return no proof and preserve the input");
                println!("native_sampling_error depth={depth} stage={stage} error_returned=true output_untouched=true input_rechecked=true seconds={:.3}", start.elapsed().as_secs_f64());
                continue;
            }
            let proof =
                native::prove(&relation, native_budget(&args[3])).expect("native fixture proof");
            std::fs::write(&args[2], &proof).expect("write proof");
            println!(
                "native_proving depth={depth} proof_bytes={} seconds={:.3} context_bound={}",
                proof.len(),
                start.elapsed().as_secs_f64(),
                args.get(4).is_some()
            );
            continue;
        }
        if export_depth.is_some() {
            if args[0] == "--check-portable-fixture" {
                use quil_lattice_ct::confidential::relation::backend::portable::PortableWitnessChecker;
                let start = Instant::now();
                let mut checker = PortableWitnessChecker::default();
                let counts = relation
                    .submit_private_relation(&mut checker)
                    .expect("portable complete relation check");
                println!("{{\"scope\":\"portable private-assignment check; no proof\",\"depth\":{depth},\"inputs\":2,\"outputs\":2,\"binary_polynomials\":{},\"scalar_equations\":{},\"linear_equations\":{},\"selection_equations\":{},\"check_seconds\":{:.6},\"serialized_proof_bytes\":null}}", counts.original_binary_polynomials + counts.auxiliary_binary_polynomials, counts.scalar_equations, counts.linear_equations, counts.selection_equations, start.elapsed().as_secs_f64());
                continue;
            }
            // Every seed above is fixed public benchmark data. Never connect
            // this diagnostic stream to wallet or live transaction witnesses.
            let stdout = std::io::stdout();
            let mut sink = backend_fixture::FixtureSink(std::io::BufWriter::new(stdout.lock()));
            relation
                .submit_private_relation(&mut sink)
                .expect("fixture submission");
            continue;
        }
        let compile_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        assert!(
            relation.validate_local_witness(),
            "public fixture satisfies every constraint"
        );
        let check_seconds = start.elapsed().as_secs_f64();
        let base = relation.shape();
        let extra = relation.membership_shape();
        let scalar_plan = relation
            .scalar_backend_plan()
            .expect("bounded scalar backend translation");
        assert!(scalar_plan.validate_local_witness());
        let start = Instant::now();
        let backend = relation
            .backend_submission_counts()
            .expect("public backend allocation plan");
        let backend_plan_seconds = start.elapsed().as_secs_f64();
        let public_bytes = root.to_bytes().len()
            + images
                .iter()
                .map(|image| image.identity_bytes().unwrap().len())
                .sum::<usize>()
            + (2..4)
                .map(|i| {
                    commitments[i].to_bytes().len()
                        + key
                            .owner_key(&notes[i].owner)
                            .identity_bytes()
                            .unwrap()
                            .len()
                })
                .sum::<usize>();
        assert_eq!(public_bytes, NODE_BYTES + 4 * IDENTITY_BYTES + 2 * 10368);
        println!(concat!(
            "{{\"scope\":\"local full input relation with SHAKE ownership; no ZK proof\",",
            "\"inputs\":2,\"outputs\":2,\"depth\":{},",
            "\"setup_seconds\":{:.6},\"compile_seconds\":{:.6},\"private_assignment_check_seconds\":{:.6},",
            "\"binary_polynomials\":{},\"binary_coefficient_storage_bytes\":{},",
            "\"linear_ring_equations\":{},\"scalar_equations\":{},\"quadratic_selection_equations\":{},",
            "\"encoded_public_components_excluding_memos_bytes\":{},",
            "\"scalar_backend_modulus\":274877906837,\"scalar_residual_bound\":{},",
            "\"backend_auxiliary_binary_polynomials\":{},\"backend_short_polynomials\":{},\"backend_linear_equations\":{},\"backend_plan_seconds\":{:.6},",
            "\"serialized_proof_bytes\":null,\"complete_transaction_bytes\":null}}"
        ), depth, setup_seconds, compile_seconds, check_seconds,
            base.binary_polynomials, base.binary_polynomials * 256 * 8,
            base.ring_equations + extra.hash_ring_equations,
            base.scalar_equations, extra.quadratic_selection_equations, public_bytes, scalar_plan.max_residual_bound(),
            backend.auxiliary_binary_polynomials, backend.short_polynomials, backend.linear_equations, backend_plan_seconds);
    }
}

#[cfg(feature = "native-proof")]
fn native_budget(
    mib: &str,
) -> quil_lattice_ct::confidential::relation::backend::native::NativeBudget {
    quil_lattice_ct::confidential::relation::backend::native::NativeBudget {
        max_native_bytes: mib
            .parse::<usize>()
            .expect("numeric MiB")
            .checked_mul(1 << 20)
            .expect("native budget fits usize"),
    }
}
