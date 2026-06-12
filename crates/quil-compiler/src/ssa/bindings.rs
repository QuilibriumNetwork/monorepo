//! Variable bindings in SSA. Port of `ssa/bindings.go`.

use std::collections::HashMap;

use super::value::ValueId;

/// A single variable binding.
#[derive(Debug, Clone)]
pub struct Binding {
    pub name: String,
    pub value_id: ValueId,
    pub block_id: usize,
}

/// Bindings tracks variable → SSA value mappings per block.
#[derive(Debug, Clone)]
pub struct Bindings {
    /// block_id → (name → value_id)
    scopes: Vec<HashMap<String, ValueId>>,
}

impl Bindings {
    pub fn new() -> Self {
        Bindings {
            scopes: vec![HashMap::new()],
        }
    }

    /// Push a new scope.
    pub fn push_scope(&mut self) {
        let current = self.scopes.last().cloned().unwrap_or_default();
        self.scopes.push(current);
    }

    /// Pop the current scope.
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Define a variable in the current scope.
    pub fn define(&mut self, name: &str, value_id: ValueId) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), value_id);
        }
    }

    /// Look up a variable in the current scope chain.
    pub fn lookup(&self, name: &str) -> Option<ValueId> {
        for scope in self.scopes.iter().rev() {
            if let Some(&id) = scope.get(name) {
                return Some(id);
            }
        }
        None
    }

    /// Set (overwrite) a variable in the current scope.
    pub fn set(&mut self, name: &str, value_id: ValueId) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), value_id);
        }
    }
}
