// src/lib.rs

use core::fmt;
use std::error::Error;
use std::ffi::CString;
use std::os::raw::{c_char, c_void, c_int};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};


uniffi::include_scaffolding!("lib");

#[derive(Debug, Clone)]
pub struct FerretError(pub String);

impl fmt::Display for FerretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for FerretError {}

// Opaque pointer types
pub enum NetIO_t {}
pub enum FerretCOT_t {}
pub enum block_t {}
pub type NetIO_ptr = *mut NetIO_t;
pub type FerretCOT_ptr = *mut FerretCOT_t;
pub type block_ptr = *mut block_t;

// Constants
pub const ALICE: i32 = 1;
pub const BOB: i32 = 2;

// FFI declarations
#[link(name = "emp_bridge")]
extern "C" {
    pub fn create_netio(party: c_int, address: *const c_char, port: c_int) -> NetIO_ptr;
    pub fn free_netio(io: NetIO_ptr);

    pub fn create_ferret_cot(party: c_int, threads: c_int, io: NetIO_ptr, malicious: bool) -> FerretCOT_ptr;
    pub fn free_ferret_cot(ot: FerretCOT_ptr);

    pub fn get_delta(ot: FerretCOT_ptr) -> block_ptr;

    pub fn allocate_blocks(length: usize) -> block_ptr;
    pub fn free_blocks(blocks: block_ptr);

    pub fn send_cot(ot: FerretCOT_ptr, b0: block_ptr, length: usize);
    pub fn recv_cot(ot: FerretCOT_ptr, br: block_ptr, choices: *const bool, length: usize);

    pub fn send_rot(ot: FerretCOT_ptr, b0: block_ptr, b1: block_ptr, length: usize);
    pub fn recv_rot(ot: FerretCOT_ptr, br: block_ptr, choices: *const bool, length: usize);
    
    pub fn get_block_data(blocks: block_ptr, index: usize, buffer: *mut u8, buffer_len: usize) -> usize;
    pub fn set_block_data(blocks: block_ptr, index: usize, data: *const u8, data_len: usize);
}

// Safe Rust wrapper for NetIO
#[derive(Debug)]
pub struct NetIO {
    pub(crate) inner: Mutex<NetIO_ptr>,
}

unsafe impl Send for NetIO {}
unsafe impl Sync for NetIO {}

impl NetIO {
    pub fn new(party: i32, address: Option<String>, port: i32) -> Self {
        let c_addr = match address.clone() {
            Some(addr) => if addr == "" {
              std::ptr::null_mut()
            } else {
              CString::new(addr).unwrap().into_raw()
            },
            None => std::ptr::null_mut(),
        };

        let inner = unsafe { create_netio(party, c_addr as *const c_char, port) };
        
        // Clean up the CString if it was created
        if !c_addr.is_null() {
            unsafe { let _ = CString::from_raw(c_addr); }
        }

        NetIO { inner: Mutex::new(inner) }
    }
}

impl NetIO {
    pub(crate) fn get_ptr(&self) -> NetIO_ptr {
        *self.inner.lock().unwrap()
    }
}

impl Drop for NetIO {
    fn drop(&mut self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { free_netio(ptr) }
        }
    }
}

// Safe Rust wrapper for block arrays
#[derive(Debug)]
pub struct BlockArray {
    pub(crate) inner: Mutex<block_ptr>,
    pub(crate) length: u64,
}

unsafe impl Send for BlockArray {}
unsafe impl Sync for BlockArray {}

impl BlockArray {
    pub fn new(length: u64) -> Self {
        let inner = unsafe { allocate_blocks(length as usize) };
        BlockArray { inner: Mutex::new(inner), length }
    }

    pub fn get_block_data(&self, index: u64) -> Vec<u8> {
      if index >= self.length {
          return Vec::new();
      }
      
      let ptr = *self.inner.lock().unwrap();
      if ptr.is_null() {
          return Vec::new();
      }
      
      // blocks are 16 bytes (128 bits) each
      const BLOCK_SIZE: usize = 16;
      
      let mut buffer = vec![0u8; BLOCK_SIZE];
      let actual_size = unsafe { 
          get_block_data(ptr, index as usize, buffer.as_mut_ptr(), buffer.len())
      };
      
      buffer.truncate(actual_size);
      buffer
  }
  
  pub fn set_block_data(&self, index: u64, data: Vec<u8>) {
      if index >= self.length {
          return;
      }
      
      let ptr = *self.inner.lock().unwrap();
      if ptr.is_null() || data.is_empty() {
          return;
      }
      
      unsafe {
          set_block_data(ptr, index as usize, data.as_ptr(), data.len());
      }
  }
}

impl BlockArray {
  fn get_ptr(&self) -> block_ptr {
      *self.inner.lock().unwrap()
  }
}

impl Drop for BlockArray {
    fn drop(&mut self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { free_blocks(ptr) }
        }
    }
}

#[derive(Debug)]
pub struct FerretCOT {
    pub(crate) inner: Mutex<FerretCOT_ptr>,
}

unsafe impl Send for FerretCOT {}
unsafe impl Sync for FerretCOT {}

impl FerretCOT {
    pub fn new(party: i32, threads: i32, netio: &NetIO, malicious: bool) -> Self {
        let inner = unsafe { create_ferret_cot(party, threads, netio.get_ptr(), malicious) };
          
        FerretCOT { 
            inner: Mutex::new(inner),
        }
    }

    pub fn get_delta(&self) -> BlockArray {
        let ptr = *self.inner.lock().unwrap();
        let delta_ptr = unsafe { get_delta(ptr) };
        BlockArray { inner: Mutex::new(delta_ptr), length: 1 }
    }

    pub fn send_cot(&self, b0: &BlockArray, length: u64) {
        let ptr = *self.inner.lock().unwrap();
        unsafe { send_cot(ptr, b0.get_ptr(), length as usize) }
    }

    pub fn recv_cot(&self, br: &BlockArray, choices: &Vec<bool>, length: u64) {
        let ptr = *self.inner.lock().unwrap();
        unsafe { recv_cot(ptr, br.get_ptr(), choices.as_ptr(), length as usize) }
    }

    pub fn send_rot(&self, b0: &BlockArray, b1: &BlockArray, length: u64) {
        let ptr = *self.inner.lock().unwrap();
        unsafe { send_rot(ptr, b0.get_ptr(), b1.get_ptr(), length as usize) }
    }

    pub fn recv_rot(&self, br: &BlockArray, choices: &Vec<bool>, length: u64) {
        let ptr = *self.inner.lock().unwrap();
        unsafe { recv_rot(ptr, br.get_ptr(), choices.as_ptr(), length as usize) }
    }
}

impl Drop for FerretCOT {
    fn drop(&mut self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { free_ferret_cot(ptr) }
        }
    }
}

// todo: when uniffi 0.28 is available for go bindgen, nuke this entire monstrosity from orbit:

pub struct NetIOManager {
  pub netio: Arc<NetIO>,
}

pub struct BlockArrayManager {
  pub block_array: Arc<BlockArray>,
}

pub struct FerretCOTManager {
  pub ferret_cot: Arc<FerretCOT>,
  pub party: i32,
  pub b0: Arc<BlockArrayManager>,
  pub b1: Option<Arc<BlockArrayManager>>,
  pub choices: Vec<bool>,
  pub length: u64,
}

impl FerretCOTManager {
  pub fn send_cot(&self) {
      self.ferret_cot.send_cot(&self.b0.block_array, self.length)
  }

  pub fn recv_cot(&self) {
      self.ferret_cot.recv_cot(&self.b0.block_array, &self.choices, self.length)
  }

  pub fn send_rot(&self) {
      self.ferret_cot.send_rot(&self.b0.block_array, &self.b1.as_ref().unwrap().block_array, self.length)
  }

  pub fn recv_rot(&self) {
      self.ferret_cot.recv_rot(&self.b0.block_array, &self.choices, self.length)
  }

  pub fn get_block_data(&self, block_choice: u8, index: u64) -> Vec<u8> {
      if block_choice == 0 {
        self.b0.block_array.get_block_data(index)
      } else {
        self.b1.as_ref().unwrap().block_array.get_block_data(index)
      }
  }

  pub fn set_block_data(&self, block_choice: u8, index: u64, data: Vec<u8>) {
      if block_choice == 0 {
        self.b0.block_array.set_block_data(index, data)
      } else {
        self.b1.as_ref().unwrap().block_array.set_block_data(index, data)
      }
  }
}

pub fn create_netio_manager(party: i32, address: Option<String>, port: i32) -> Arc<NetIOManager> {
  let netio = Arc::new(NetIO::new(party, address, port));
  Arc::new(NetIOManager { netio })
}

pub fn create_block_array_manager(length: u64) -> Arc<BlockArrayManager> {
  let block_array = Arc::new(BlockArray::new(length));
  Arc::new(BlockArrayManager { block_array })
}

pub fn create_ferret_cot_manager(party: i32, threads: i32, length: u64, choices: Vec<bool>, netio: &Arc<NetIOManager>, malicious: bool) -> Arc<FerretCOTManager> {
  let ferret_cot = Arc::new(FerretCOT::new(party, threads, &netio.netio, malicious));
  Arc::new(FerretCOTManager { ferret_cot, party, b0: create_block_array_manager(length), b1: if party == 2 { None } else { Some(create_block_array_manager(length)) }, choices, length })
}