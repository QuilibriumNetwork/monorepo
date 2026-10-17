use curve25519_dalek::Scalar;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
  let smsize: usize = 100;
  let msize = smsize*smsize;
  let depth: usize = 4;
  let players: usize = 9;
  let dealers: usize = 3;

  //todo parties should be + 1
  let is1 = rpm::rpm_generate_initial_shares(msize as u64, depth as u64, dealers as u64, players as u64);
  let is2 = rpm::rpm_generate_initial_shares(msize as u64, depth as u64, dealers as u64, players as u64);
  let is3 = rpm::rpm_generate_initial_shares(msize as u64, depth as u64, dealers as u64, players as u64);
  let (m1, r1) = (is1.ms, is1.rs);
  let (m2, r2) = (is2.ms, is2.rs);
  let (m3, r3) = (is3.ms, is3.rs);

  let mut ms = vec![vec![vec![vec![vec![vec![[0u8; 32]; smsize]; smsize]; smsize]; depth]; dealers]; players];
  let mut rs = vec![vec![vec![vec![[0u8; 32]; msize]; depth]; dealers]; players];

  let mut mc = Vec::<Vec<Vec<Vec<Vec<[u8; 32]>>>>>::with_capacity(players);
  let mut rc = Vec::<Vec<Vec<[u8; 32]>>>::with_capacity(players);
  let mut mrmc = Vec::<Vec<Vec<Vec<Vec<[u8; 32]>>>>>::with_capacity(players);
  let mut mccs = Vec::<Vec<Vec<Vec<[u8; 32]>>>>::with_capacity(players);
  let mut rccs = Vec::<Vec<[u8; 32]>>::with_capacity(players);
  for i in 0..players {
      for j in 0..depth {
          for k in 0..smsize {
              ms[i][0][j][k] = m1[j][k][i].clone();
              ms[i][1][j][k] = m2[j][k][i].clone();
              ms[i][2][j][k] = m3[j][k][i].clone();
          }

          rs[i][0][j] = r1[j][i].clone();
          rs[i][1][j] = r2[j][i].clone();
          rs[i][2][j] = r3[j][i].clone();
      }

      let cs = rpm::rpm_combine_shares_and_mask(ms[i].clone(), rs[i].clone(), msize as u64, depth as u64, dealers as u64);
      let (m, r, mrm) = (cs.ms, cs.rs, cs.mrms);
      let sp = rpm::rpm_sketch_propose(m.clone(), r.clone());
      let (mcc, rcc) = (sp.mp, sp.rp);

      mc.push(m);
      rc.push(r);
      mrmc.push(mrm);
      mccs.push(mcc);
      rccs.push(rcc);
  }

  let mut xs = vec![vec![[0u8; 32]; msize]; players];

  for i in 0..msize {
      let xsi = rpm::gen_poly_frags(&Scalar::from(i as u64), 9, 3);
      for j in 0..9 {
          xs[j][i] = (Scalar::from_bytes_mod_order(xsi[j]) + Scalar::from_bytes_mod_order(rc[j][0][i])).to_bytes();
      }
  }
  
  let mut group = c.benchmark_group("rpm");
  group.sample_size(10);
  group.bench_function(format!("rpm init {}", msize), |b| b.iter(|| black_box(rpm::rpm_generate_initial_shares(msize as u64, depth as u64, 3, 9))));
  group.bench_function(format!("rpm combine {}", msize), |b| b.iter(|| black_box(rpm::rpm_combine_shares_and_mask(ms[0].clone(), rs[0].clone(), msize as u64, depth as u64, dealers as u64))));
  group.bench_function(format!("rpm sketch propose {}", msize), |b| b.iter(|| black_box(rpm::rpm_sketch_propose(mc[0].clone(), rc[0].clone()))));
  group.bench_function(format!("rpm sketch verify {}", msize), |b| b.iter(|| black_box(rpm::rpm_sketch_verify(mccs.clone(), rccs.clone(), dealers as u64))));
  group.bench_function(format!("rpm permute {}", msize), |b| b.iter(|| black_box(rpm::rpm_permute(xs.clone(), mc[0].clone(), rc[0].clone(), mrmc[0].clone(), 0, vec![1,2,3,4,5,6,7,8,9]))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);