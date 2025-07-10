use std::sync::{Once};
use std::{mem::MaybeUninit};
use std::collections::HashMap;
use serde_json;
use hex;
use crate::bls48581::big;
use crate::bls48581::ecp;
use crate::bls48581::ecp8;
use crate::bls48581::bls256;

pub struct SingletonKZGSetup {
  pub RootOfUnityBLS48581: HashMap<u64, big::BIG>,
  pub RootsOfUnityBLS48581: HashMap<u64, Vec<big::BIG>>,
  pub ReverseRootsOfUnityBLS48581: HashMap<u64, Vec<big::BIG>>,
  pub CeremonyBLS48581G1: Vec<ecp::ECP>,
  pub CeremonyBLS48581G2: Vec<ecp8::ECP8>,
  pub FFTBLS48581: HashMap<u64, Vec<ecp::ECP>>,
}

pub fn singleton() -> &'static SingletonKZGSetup {
  static mut SINGLETON: MaybeUninit<SingletonKZGSetup> = MaybeUninit::uninit();
  static ONCE: Once = Once::new();

  unsafe {
    ONCE.call_once(|| {
      bls256::init();
      let bytes = include_bytes!("optimized_ceremony.json");
      let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
      let mut blsg1 = Vec::<ecp::ECP>::new();
      let mut blsg2 = Vec::<ecp8::ECP8>::new();
      let mut rootOfUnity = HashMap::<u64, big::BIG>::new();
      let mut rootsOfUnity = HashMap::<u64, Vec<big::BIG>>::new();
      let mut reverseRootsOfUnity = HashMap::<u64, Vec<big::BIG>>::new();
      let mut ffts = HashMap::<u64, Vec<ecp::ECP>>::new();

      for power in v["powersOfTau"]["G1Powers"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        blsg1.push(ecp::ECP::frombytes(&p));
      }

      for power in v["powersOfTau"]["G2Powers"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        blsg2.push(ecp8::ECP8::frombytes(&p));
      }

      {
        let root = v["sized"]["rootOfUnity"]["rootOfUnity16"].clone();
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootOfUnity.insert(16, big::BIG::frombytes(&r));
      }

      {
        let root = v["sized"]["rootOfUnity"]["rootOfUnity32"].clone();
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootOfUnity.insert(32, big::BIG::frombytes(&r));
      }

      {
        let root = v["sized"]["rootOfUnity"]["rootOfUnity64"].clone();
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootOfUnity.insert(64, big::BIG::frombytes(&r));
      }

      {
        let root = v["sized"]["rootOfUnity"]["rootOfUnity128"].clone();
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootOfUnity.insert(128, big::BIG::frombytes(&r));
      }

      {
        let root = v["sized"]["rootOfUnity"]["rootOfUnity256"].clone();
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootOfUnity.insert(256, big::BIG::frombytes(&r));
      }

      // {
      //   let root = v["sized"]["rootOfUnity"]["rootOfUnity512"].clone();
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootOfUnity.insert(512, big::BIG::frombytes(&r));
      // }

      // {
      //   let root = v["sized"]["rootOfUnity"]["rootOfUnity1024"].clone();
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootOfUnity.insert(1024, big::BIG::frombytes(&r));
      // }

      // {
      //   let root = v["sized"]["rootOfUnity"]["rootOfUnity2048"].clone();
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootOfUnity.insert(2048, big::BIG::frombytes(&r));
      // }

      // {
      //   let root = v["sized"]["rootOfUnity"]["rootOfUnity65536"].clone();
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootOfUnity.insert(65536, big::BIG::frombytes(&r));
      // }

      let mut rootsOfUnity16 = Vec::<big::BIG>::new();
      for root in v["sized"]["rootsOfUnity"]["rootsOfUnity16"].as_array().unwrap() {
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootsOfUnity16.push(big::BIG::frombytes(&r));
      }
      rootsOfUnity.insert(16, rootsOfUnity16.clone());
      reverseRootsOfUnity.insert(16, rootsOfUnity16.into_iter().rev().collect());

      let mut rootsOfUnity32 = Vec::<big::BIG>::new();
      for root in v["sized"]["rootsOfUnity"]["rootsOfUnity32"].as_array().unwrap() {
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootsOfUnity32.push(big::BIG::frombytes(&r));
      }
      rootsOfUnity.insert(32, rootsOfUnity32.clone());
      reverseRootsOfUnity.insert(32, rootsOfUnity32.into_iter().rev().collect());

      let mut rootsOfUnity64 = Vec::<big::BIG>::new();
      for root in v["sized"]["rootsOfUnity"]["rootsOfUnity64"].as_array().unwrap() {
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootsOfUnity64.push(big::BIG::frombytes(&r));
      }
      rootsOfUnity.insert(64, rootsOfUnity64.clone());
      reverseRootsOfUnity.insert(64, rootsOfUnity64.into_iter().rev().collect());

      let mut rootsOfUnity128 = Vec::<big::BIG>::new();
      for root in v["sized"]["rootsOfUnity"]["rootsOfUnity128"].as_array().unwrap() {
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootsOfUnity128.push(big::BIG::frombytes(&r));
      }
      rootsOfUnity.insert(128, rootsOfUnity128.clone());
      reverseRootsOfUnity.insert(128, rootsOfUnity128.into_iter().rev().collect());

      let mut rootsOfUnity256 = Vec::<big::BIG>::new();
      for root in v["sized"]["rootsOfUnity"]["rootsOfUnity256"].as_array().unwrap() {
        let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        rootsOfUnity256.push(big::BIG::frombytes(&r));
      }
      rootsOfUnity.insert(256, rootsOfUnity256.clone());
      reverseRootsOfUnity.insert(256, rootsOfUnity256.into_iter().rev().collect());

      // let mut rootsOfUnity512 = Vec::<big::BIG>::new();
      // for root in v["sized"]["rootsOfUnity"]["rootsOfUnity512"].as_array().unwrap() {
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootsOfUnity512.push(big::BIG::frombytes(&r));
      // }
      // rootsOfUnity.insert(512, rootsOfUnity512.clone());
      // reverseRootsOfUnity.insert(512, rootsOfUnity512.into_iter().rev().collect());

      // let mut rootsOfUnity1024 = Vec::<big::BIG>::new();
      // for root in v["sized"]["rootsOfUnity"]["rootsOfUnity1024"].as_array().unwrap() {
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootsOfUnity1024.push(big::BIG::frombytes(&r));
      // }
      // rootsOfUnity.insert(1024, rootsOfUnity1024.clone());
      // reverseRootsOfUnity.insert(1024, rootsOfUnity1024.into_iter().rev().collect());

      // let mut rootsOfUnity2048 = Vec::<big::BIG>::new();
      // for root in v["sized"]["rootsOfUnity"]["rootsOfUnity2048"].as_array().unwrap() {
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootsOfUnity2048.push(big::BIG::frombytes(&r));
      // }
      // rootsOfUnity.insert(2048, rootsOfUnity2048.clone());
      // reverseRootsOfUnity.insert(2048, rootsOfUnity2048.into_iter().rev().collect());

      // let mut rootsOfUnity65536 = Vec::<big::BIG>::new();
      // for root in v["sized"]["rootsOfUnity"]["rootsOfUnity65536"].as_array().unwrap() {
      //   let r = hex::decode(root.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   rootsOfUnity65536.push(big::BIG::frombytes(&r));
      // }
      // rootsOfUnity.insert(65536, rootsOfUnity65536.clone());
      // reverseRootsOfUnity.insert(65536, rootsOfUnity65536.into_iter().rev().collect());
      
      let mut f16 = Vec::<ecp::ECP>::new();
      for power in v["sized"]["G1FFT"]["G1FFT16"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        f16.push(ecp::ECP::frombytes(&p));
      }
      ffts.insert(16, f16);

      let mut f32 = Vec::<ecp::ECP>::new();
      for power in v["sized"]["G1FFT"]["G1FFT32"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        f32.push(ecp::ECP::frombytes(&p));
      }
      ffts.insert(32, f32);

      let mut f64 = Vec::<ecp::ECP>::new();
      for power in v["sized"]["G1FFT"]["G1FFT64"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        f64.push(ecp::ECP::frombytes(&p));
      }
      ffts.insert(64, f64);

      let mut f128 = Vec::<ecp::ECP>::new();
      for power in v["sized"]["G1FFT"]["G1FFT128"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        f128.push(ecp::ECP::frombytes(&p));
      }
      ffts.insert(128, f128);

      let mut f256 = Vec::<ecp::ECP>::new();
      for power in v["sized"]["G1FFT"]["G1FFT256"].as_array().unwrap() {
        let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        f256.push(ecp::ECP::frombytes(&p));
      }
      ffts.insert(256, f256);

      // let mut f512 = Vec::<ecp::ECP>::new();
      // for power in v["sized"]["G1FFT"]["G1FFT512"].as_array().unwrap() {
      //   let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   f512.push(ecp::ECP::frombytes(&p));
      // }
      // ffts.insert(512, f512);

      // let mut f1024 = Vec::<ecp::ECP>::new();
      // for power in v["sized"]["G1FFT"]["G1FFT1024"].as_array().unwrap() {
      //   let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   f1024.push(ecp::ECP::frombytes(&p));
      // }
      // ffts.insert(1024, f1024);

      // let mut f2048 = Vec::<ecp::ECP>::new();
      // for power in v["sized"]["G1FFT"]["G1FFT2048"].as_array().unwrap() {
      //   let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   f2048.push(ecp::ECP::frombytes(&p));
      // }
      // ffts.insert(2048, f2048);

      // let mut f65536 = Vec::<ecp::ECP>::new();
      // for power in v["sized"]["G1FFT"]["G1FFT65536"].as_array().unwrap() {
      //   let p = hex::decode(power.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
      //   f65536.push(ecp::ECP::frombytes(&p));
      // }
      // ffts.insert(65536, f65536);

      let singleton = SingletonKZGSetup {
        RootOfUnityBLS48581: rootOfUnity,
        RootsOfUnityBLS48581: rootsOfUnity,
        ReverseRootsOfUnityBLS48581: reverseRootsOfUnity,
        CeremonyBLS48581G1: blsg1,
        CeremonyBLS48581G2: blsg2,
        FFTBLS48581: ffts,
      };

      SINGLETON.write(singleton);
    });

    SINGLETON.assume_init_ref()
  }
}