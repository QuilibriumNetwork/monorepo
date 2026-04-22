//! SSA basic blocks. Port of `ssa/block.go`.

use std::fmt;

use super::instructions::Instr;

/// Basic block in SSA form.
#[derive(Debug, Clone)]
pub struct Block {
    pub id: usize,
    pub name: String,
    pub instructions: Vec<Instr>,
    /// Successor block IDs.
    pub succs: Vec<usize>,
    /// Predecessor block IDs.
    pub preds: Vec<usize>,
    /// Whether this block is sealed (all predecessors known).
    pub sealed: bool,
    /// Whether this block is dead (unreachable).
    pub dead: bool,
}

impl Block {
    pub fn new(id: usize, name: &str) -> Self {
        Block {
            id,
            name: name.to_string(),
            instructions: Vec::new(),
            succs: Vec::new(),
            preds: Vec::new(),
            sealed: false,
            dead: false,
        }
    }

    pub fn add_instr(&mut self, instr: Instr) {
        self.instructions.push(instr);
    }

    pub fn add_succ(&mut self, block_id: usize) {
        if !self.succs.contains(&block_id) {
            self.succs.push(block_id);
        }
    }

    pub fn add_pred(&mut self, block_id: usize) {
        if !self.preds.contains(&block_id) {
            self.preds.push(block_id);
        }
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}:", self.name)?;
        for instr in &self.instructions {
            writeln!(f, "  {}", instr)?;
        }
        Ok(())
    }
}
