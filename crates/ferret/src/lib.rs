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
pub enum BufferIO_t {}
pub enum FerretCOT_t {}
pub enum FerretCOT_Buffer_t {}
pub enum block_t {}
pub type NetIO_ptr = *mut NetIO_t;
pub type BufferIO_ptr = *mut BufferIO_t;
pub type FerretCOT_ptr = *mut FerretCOT_t;
pub type FerretCOT_Buffer_ptr = *mut FerretCOT_Buffer_t;
pub type block_ptr = *mut block_t;

// Constants
pub const ALICE: i32 = 1;
pub const BOB: i32 = 2;

// FFI declarations
#[link(name = "emp_bridge")]
extern "C" {
    // NetIO (TCP-based)
    pub fn create_netio(party: c_int, address: *const c_char, port: c_int) -> NetIO_ptr;
    pub fn free_netio(io: NetIO_ptr);

    // BufferIO (message-based)
    pub fn create_buffer_io(initial_cap: i64) -> BufferIO_ptr;
    pub fn free_buffer_io(io: BufferIO_ptr);
    pub fn buffer_io_fill_recv(io: BufferIO_ptr, data: *const u8, len: usize) -> c_int;
    pub fn buffer_io_drain_send(io: BufferIO_ptr, out_buffer: *mut u8, max_len: usize) -> usize;
    pub fn buffer_io_send_size(io: BufferIO_ptr) -> usize;
    pub fn buffer_io_recv_available(io: BufferIO_ptr) -> usize;
    pub fn buffer_io_set_timeout(io: BufferIO_ptr, timeout_ms: i64);
    pub fn buffer_io_set_error(io: BufferIO_ptr, message: *const c_char);
    pub fn buffer_io_clear(io: BufferIO_ptr);

    // FerretCOT (TCP-based)
    pub fn create_ferret_cot(party: c_int, threads: c_int, io: NetIO_ptr, malicious: bool) -> FerretCOT_ptr;
    pub fn free_ferret_cot(ot: FerretCOT_ptr);
    pub fn get_delta(ot: FerretCOT_ptr) -> block_ptr;
    pub fn send_cot(ot: FerretCOT_ptr, b0: block_ptr, length: usize);
    pub fn recv_cot(ot: FerretCOT_ptr, br: block_ptr, choices: *const bool, length: usize);
    pub fn send_rot(ot: FerretCOT_ptr, b0: block_ptr, b1: block_ptr, length: usize);
    pub fn recv_rot(ot: FerretCOT_ptr, br: block_ptr, choices: *const bool, length: usize);

    // FerretCOT (Buffer-based)
    // NOTE: create_ferret_cot_buffer does NOT run setup automatically.
    // You must call setup_ferret_cot_buffer after both parties have their
    // message transport active (i.e., can send/receive data).
    pub fn create_ferret_cot_buffer(party: c_int, threads: c_int, io: BufferIO_ptr, malicious: bool) -> FerretCOT_Buffer_ptr;
    pub fn free_ferret_cot_buffer(ot: FerretCOT_Buffer_ptr);
    pub fn setup_ferret_cot_buffer(ot: FerretCOT_Buffer_ptr, party: c_int) -> c_int;
    pub fn get_delta_buffer(ot: FerretCOT_Buffer_ptr) -> block_ptr;
    pub fn send_cot_buffer(ot: FerretCOT_Buffer_ptr, b0: block_ptr, length: usize) -> c_int;
    pub fn recv_cot_buffer(ot: FerretCOT_Buffer_ptr, br: block_ptr, choices: *const bool, length: usize) -> c_int;
    pub fn send_rot_buffer(ot: FerretCOT_Buffer_ptr, b0: block_ptr, b1: block_ptr, length: usize) -> c_int;
    pub fn recv_rot_buffer(ot: FerretCOT_Buffer_ptr, br: block_ptr, choices: *const bool, length: usize) -> c_int;

    // Block operations
    pub fn allocate_blocks(length: usize) -> block_ptr;
    pub fn free_blocks(blocks: block_ptr);
    pub fn get_block_data(blocks: block_ptr, index: usize, buffer: *mut u8, buffer_len: usize) -> usize;
    pub fn set_block_data(blocks: block_ptr, index: usize, data: *const u8, data_len: usize);

    // State serialization (for persistent storage instead of file-based)
    pub fn ferret_cot_state_size(ot: FerretCOT_ptr) -> i64;
    pub fn ferret_cot_buffer_state_size(ot: FerretCOT_Buffer_ptr) -> i64;
    pub fn ferret_cot_assemble_state(ot: FerretCOT_ptr, buffer: *mut u8, buffer_size: i64) -> c_int;
    pub fn ferret_cot_buffer_assemble_state(ot: FerretCOT_Buffer_ptr, buffer: *mut u8, buffer_size: i64) -> c_int;
    pub fn ferret_cot_disassemble_state(ot: FerretCOT_ptr, buffer: *const u8, buffer_size: i64) -> c_int;
    pub fn ferret_cot_buffer_disassemble_state(ot: FerretCOT_Buffer_ptr, buffer: *const u8, buffer_size: i64) -> c_int;
    pub fn ferret_cot_is_setup(ot: FerretCOT_ptr) -> bool;
    pub fn ferret_cot_buffer_is_setup(ot: FerretCOT_Buffer_ptr) -> bool;
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

// =============================================================================
// BufferIO - Message-based IO for Ferret OT (no TCP required)
// =============================================================================

#[derive(Debug)]
pub struct BufferIO {
    pub(crate) inner: Mutex<BufferIO_ptr>,
}

unsafe impl Send for BufferIO {}
unsafe impl Sync for BufferIO {}

impl BufferIO {
    pub fn new(initial_cap: i64) -> Self {
        let inner = unsafe { create_buffer_io(initial_cap) };
        BufferIO { inner: Mutex::new(inner) }
    }

    pub fn fill_recv(&self, data: &[u8]) -> Result<(), String> {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return Err("BufferIO is null".to_string());
        }
        let result = unsafe { buffer_io_fill_recv(ptr, data.as_ptr(), data.len()) };
        if result == 0 {
            Ok(())
        } else {
            Err("Failed to fill recv buffer".to_string())
        }
    }

    pub fn drain_send(&self, max_len: usize) -> Vec<u8> {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return Vec::new();
        }
        let mut buffer = vec![0u8; max_len];
        let actual_len = unsafe { buffer_io_drain_send(ptr, buffer.as_mut_ptr(), max_len) };
        buffer.truncate(actual_len);
        buffer
    }

    pub fn send_size(&self) -> usize {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return 0;
        }
        unsafe { buffer_io_send_size(ptr) }
    }

    pub fn recv_available(&self) -> usize {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return 0;
        }
        unsafe { buffer_io_recv_available(ptr) }
    }

    pub fn set_timeout(&self, timeout_ms: i64) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { buffer_io_set_timeout(ptr, timeout_ms) }
        }
    }

    pub fn set_error(&self, message: &str) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            let c_msg = CString::new(message).unwrap();
            unsafe { buffer_io_set_error(ptr, c_msg.as_ptr()) }
        }
    }

    pub fn clear(&self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { buffer_io_clear(ptr) }
        }
    }

    pub(crate) fn get_ptr(&self) -> BufferIO_ptr {
        *self.inner.lock().unwrap()
    }
}

impl Drop for BufferIO {
    fn drop(&mut self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { free_buffer_io(ptr) }
        }
    }
}

// =============================================================================
// FerretCOTBuffer - Ferret OT using BufferIO (message-based)
// =============================================================================

#[derive(Debug)]
pub struct FerretCOTBuffer {
    pub(crate) inner: Mutex<FerretCOT_Buffer_ptr>,
}

unsafe impl Send for FerretCOTBuffer {}
unsafe impl Sync for FerretCOTBuffer {}

impl FerretCOTBuffer {
    pub fn new(party: i32, threads: i32, bufferio: &BufferIO, malicious: bool) -> Self {
        let inner = unsafe { create_ferret_cot_buffer(party, threads, bufferio.get_ptr(), malicious) };
        FerretCOTBuffer {
            inner: Mutex::new(inner),
        }
    }

    /// Run the OT setup protocol. Must be called after both parties have their
    /// BufferIO message transport active (can send/receive data).
    /// This is deferred from construction because BufferIO-based OT needs
    /// the message channel to be ready before setup can exchange data.
    /// Returns true on success, false on error.
    pub fn setup(&self, party: i32) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        let result = unsafe { setup_ferret_cot_buffer(ptr, party) };
        result == 0
    }

    /// Check if setup has been run
    pub fn is_setup(&self) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        unsafe { ferret_cot_buffer_is_setup(ptr) }
    }

    /// Get the size needed to store the OT state
    pub fn state_size(&self) -> i64 {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return 0;
        }
        unsafe { ferret_cot_buffer_state_size(ptr) }
    }

    /// Serialize OT state to a buffer for persistent storage.
    /// This allows storing setup data externally instead of in files.
    /// Returns None if serialization fails.
    pub fn assemble_state(&self) -> Option<Vec<u8>> {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return None;
        }
        let size = unsafe { ferret_cot_buffer_state_size(ptr) };
        if size <= 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let result = unsafe { ferret_cot_buffer_assemble_state(ptr, buffer.as_mut_ptr(), size) };
        if result == 0 {
            Some(buffer)
        } else {
            None
        }
    }

    /// Restore OT state from a buffer (created by assemble_state).
    /// This must be called INSTEAD of setup, not after.
    /// Returns true on success.
    pub fn disassemble_state(&self, data: &[u8]) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() || data.is_empty() {
            return false;
        }
        let result = unsafe { ferret_cot_buffer_disassemble_state(ptr, data.as_ptr(), data.len() as i64) };
        result == 0
    }

    pub fn get_delta(&self) -> BlockArray {
        let ptr = *self.inner.lock().unwrap();
        let delta_ptr = unsafe { get_delta_buffer(ptr) };
        BlockArray { inner: Mutex::new(delta_ptr), length: 1 }
    }

    pub fn send_cot(&self, b0: &BlockArray, length: u64) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        let result = unsafe { send_cot_buffer(ptr, b0.get_ptr(), length as usize) };
        result == 0
    }

    pub fn recv_cot(&self, br: &BlockArray, choices: &Vec<bool>, length: u64) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        let result = unsafe { recv_cot_buffer(ptr, br.get_ptr(), choices.as_ptr(), length as usize) };
        result == 0
    }

    pub fn send_rot(&self, b0: &BlockArray, b1: &BlockArray, length: u64) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        let result = unsafe { send_rot_buffer(ptr, b0.get_ptr(), b1.get_ptr(), length as usize) };
        result == 0
    }

    pub fn recv_rot(&self, br: &BlockArray, choices: &Vec<bool>, length: u64) -> bool {
        let ptr = *self.inner.lock().unwrap();
        if ptr.is_null() {
            return false;
        }
        let result = unsafe { recv_rot_buffer(ptr, br.get_ptr(), choices.as_ptr(), length as usize) };
        result == 0
    }
}

impl Drop for FerretCOTBuffer {
    fn drop(&mut self) {
        let ptr = *self.inner.lock().unwrap();
        if !ptr.is_null() {
            unsafe { free_ferret_cot_buffer(ptr) }
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

// =============================================================================
// BufferIO Manager types for UniFFI (message-based Ferret OT)
// =============================================================================

pub struct BufferIOManager {
    pub bufferio: Arc<BufferIO>,
}

impl BufferIOManager {
    /// Fill the receive buffer with data from external transport
    pub fn fill_recv(&self, data: Vec<u8>) -> bool {
        self.bufferio.fill_recv(&data).is_ok()
    }

    /// Drain data from send buffer (up to max_len bytes)
    pub fn drain_send(&self, max_len: u64) -> Vec<u8> {
        self.bufferio.drain_send(max_len as usize)
    }

    /// Get current send buffer size
    pub fn send_size(&self) -> u64 {
        self.bufferio.send_size() as u64
    }

    /// Get available bytes in receive buffer
    pub fn recv_available(&self) -> u64 {
        self.bufferio.recv_available() as u64
    }

    /// Set timeout for blocking receive (milliseconds)
    pub fn set_timeout(&self, timeout_ms: i64) {
        self.bufferio.set_timeout(timeout_ms);
    }

    /// Set error state
    pub fn set_error(&self, message: String) {
        self.bufferio.set_error(&message);
    }

    /// Clear all buffers
    pub fn clear(&self) {
        self.bufferio.clear();
    }
}

pub struct FerretCOTBufferManager {
    pub ferret_cot: Arc<FerretCOTBuffer>,
    pub party: i32,
    pub b0: Arc<BlockArrayManager>,
    pub b1: Option<Arc<BlockArrayManager>>,
    pub choices: Vec<bool>,
    pub length: u64,
}

impl FerretCOTBufferManager {
    /// Run the OT setup protocol. Must be called after both parties have their
    /// BufferIO message transport active (can send/receive data).
    /// Returns true on success, false on error.
    pub fn setup(&self) -> bool {
        self.ferret_cot.setup(self.party)
    }

    /// Check if setup has been run
    pub fn is_setup(&self) -> bool {
        self.ferret_cot.is_setup()
    }

    /// Get the size needed to store the OT state
    pub fn state_size(&self) -> i64 {
        self.ferret_cot.state_size()
    }

    /// Serialize OT state for persistent storage.
    /// Returns the serialized state, or empty vector if failed.
    pub fn assemble_state(&self) -> Vec<u8> {
        self.ferret_cot.assemble_state().unwrap_or_default()
    }

    /// Restore OT state from a buffer (created by assemble_state).
    /// This must be called INSTEAD of setup, not after.
    /// Returns true on success.
    pub fn disassemble_state(&self, data: Vec<u8>) -> bool {
        self.ferret_cot.disassemble_state(&data)
    }

    pub fn send_cot(&self) -> bool {
        self.ferret_cot.send_cot(&self.b0.block_array, self.length)
    }

    pub fn recv_cot(&self) -> bool {
        self.ferret_cot.recv_cot(&self.b0.block_array, &self.choices, self.length)
    }

    pub fn send_rot(&self) -> bool {
        self.ferret_cot.send_rot(&self.b0.block_array, &self.b1.as_ref().unwrap().block_array, self.length)
    }

    pub fn recv_rot(&self) -> bool {
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

pub fn create_buffer_io_manager(initial_cap: i64) -> Arc<BufferIOManager> {
    let bufferio = Arc::new(BufferIO::new(initial_cap));
    Arc::new(BufferIOManager { bufferio })
}

pub fn create_ferret_cot_buffer_manager(
    party: i32,
    threads: i32,
    length: u64,
    choices: Vec<bool>,
    bufferio: &Arc<BufferIOManager>,
    malicious: bool
) -> Arc<FerretCOTBufferManager> {
    let ferret_cot = Arc::new(FerretCOTBuffer::new(party, threads, &bufferio.bufferio, malicious));
    Arc::new(FerretCOTBufferManager {
        ferret_cot,
        party,
        b0: create_block_array_manager(length),
        b1: if party == 2 { None } else { Some(create_block_array_manager(length)) },
        choices,
        length,
    })
}