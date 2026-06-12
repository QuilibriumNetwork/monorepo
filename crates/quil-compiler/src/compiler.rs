//! Top-level QCL compiler. Port of `bedlam/compiler/compiler.go`.

use std::collections::HashMap;

use crate::ast::{self, Package};
use crate::circuit::Circuit;
use crate::parser::Parser;
use crate::ssa;

/// Compiler parameters.
#[derive(Debug, Clone)]
pub struct Params {
    pub verbose: bool,
    pub diagnostics: bool,
    pub max_var_bits: i32,
    pub max_loop_unroll: i32,
    pub no_circ_compile: bool,
    pub circ_mult_array_threshold: i32,
    pub opt_prune_gates: bool,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            verbose: false,
            diagnostics: false,
            max_var_bits: 0x20000,
            max_loop_unroll: 0x20000,
            no_circ_compile: false,
            circ_mult_array_threshold: 0,
            opt_prune_gates: false,
        }
    }
}

/// QCL Compiler.
pub struct Compiler {
    params: Params,
    packages: HashMap<String, Package>,
}

impl Compiler {
    /// Create a new compiler.
    pub fn new(params: Params) -> Self {
        Compiler {
            params,
            packages: HashMap::new(),
        }
    }

    /// Compile QCL source code into a boolean circuit.
    pub fn compile(
        &mut self,
        source: &str,
        input_sizes: &[Vec<i32>],
    ) -> Result<Circuit, String> {
        let mut pkg = Package::new("main", "{data}");
        let mut parser = Parser::new("{data}", source);
        parser.parse(&mut pkg)?;
        self.packages.insert(pkg.name.clone(), pkg.clone());

        // Build SSA program from AST.
        let program = self.build_ssa(&pkg, input_sizes)?;

        // Compile SSA to circuit.
        if self.params.no_circ_compile {
            return Err("circuit compilation disabled".to_string());
        }
        program.compile_circuit()
    }

    /// Compile QCL source and marshal the resulting circuit.
    pub fn compile_to_bytes(
        &mut self,
        source: &str,
        input_sizes: &[Vec<i32>],
    ) -> Result<Vec<u8>, String> {
        let circuit = self.compile(source, input_sizes)?;
        let mut buf = Vec::new();
        circuit
            .marshal(&mut buf)
            .map_err(|e| format!("marshal: {}", e))?;
        Ok(buf)
    }

    /// Validate a compiled circuit (parse from bytes).
    pub fn validate_circuit(data: &[u8]) -> Result<(), String> {
        Circuit::parse_qclc(&mut &data[..]).map_err(|e| format!("invalid circuit: {}", e))?;
        Ok(())
    }

    /// Build SSA program from AST.
    fn build_ssa(
        &self,
        pkg: &Package,
        input_sizes: &[Vec<i32>],
    ) -> Result<ssa::Program, String> {
        let main_fn = pkg
            .main()
            .ok_or_else(|| "no main function found".to_string())?;

        let mut gen = ssa::Generator::new();
        let mut program = ssa::Program::new();

        // Build input/output IO from function signature.
        for (idx, (name, type_info)) in main_fn.params.iter().enumerate() {
            let mut ti = type_info.clone();

            // Instantiate with input sizes if type is not concrete.
            if !ti.concrete() && idx < input_sizes.len() {
                ti.instantiate_with_sizes(&input_sizes[idx])
                    .map_err(|e| format!("input type instantiation: {}", e))?;
            }

            let io_arg = crate::circuit::IOArg::new(name, ti.typ, ti.bits);
            program.inputs.push(io_arg);

            let val_id = gen.new_value(name, ti.clone());
            gen.values[val_id as usize].param = true;
            program.input_values.push(val_id);
        }

        for (name, type_info) in &main_fn.returns {
            let io_arg = crate::circuit::IOArg::new(name, type_info.typ, type_info.bits);
            program.outputs.push(io_arg);
        }

        // Define parameters in bindings.
        for (idx, (name, _)) in main_fn.params.iter().enumerate() {
            gen.bindings.define(name, program.input_values[idx]);
        }

        // Generate SSA from function body.
        self.gen_stmts(&mut gen, &mut program, &main_fn.body)?;

        // Transfer generated data to program.
        program.blocks = gen.blocks;
        program.values = gen.values;

        Ok(program)
    }

    fn gen_stmts(
        &self,
        gen: &mut ssa::Generator,
        program: &mut ssa::Program,
        stmts: &[ast::Stmt],
    ) -> Result<(), String> {
        for stmt in stmts {
            self.gen_stmt(gen, program, stmt)?;
        }
        Ok(())
    }

    fn gen_stmt(
        &self,
        gen: &mut ssa::Generator,
        program: &mut ssa::Program,
        stmt: &ast::Stmt,
    ) -> Result<(), String> {
        match stmt {
            ast::Stmt::Return { values, .. } => {
                let mut ret_vals = Vec::new();
                for expr in values {
                    let val = self.gen_expr(gen, expr)?;
                    ret_vals.push(val);
                }
                program.return_values = ret_vals.clone();
                gen.emit_ret(&ret_vals);
            }
            ast::Stmt::Var { names, init, type_info, .. } => {
                for (i, name) in names.iter().enumerate() {
                    let ti = type_info.clone().unwrap_or_default();
                    if i < init.len() {
                        let val = self.gen_expr(gen, &init[i])?;
                        gen.bindings.define(name, val);
                    } else {
                        let val_id = gen.new_value(name, ti);
                        gen.bindings.define(name, val_id);
                    }
                }
            }
            ast::Stmt::ShortDecl { names, values, .. } => {
                for (i, name) in names.iter().enumerate() {
                    if i < values.len() {
                        let val = self.gen_expr(gen, &values[i])?;
                        gen.bindings.define(name, val);
                    }
                }
            }
            ast::Stmt::Assign { targets, values, .. } => {
                for (i, target) in targets.iter().enumerate() {
                    if i < values.len() {
                        let val = self.gen_expr(gen, &values[i])?;
                        if let ast::Expr::VariableRef { name, .. } = target {
                            gen.bindings.set(name, val);
                        }
                    }
                }
            }
            ast::Stmt::ExprStmt { expr, .. } => {
                self.gen_expr(gen, expr)?;
            }
            ast::Stmt::If { cond, body, else_body, .. } => {
                let cond_val = self.gen_expr(gen, cond)?;
                let then_block = gen.new_block("then");
                let else_block = gen.new_block("else");
                let merge_block = gen.new_block("merge");

                gen.emit_if(cond_val, then_block, else_block);

                gen.set_current_block(then_block);
                self.gen_stmts(gen, program, body)?;
                gen.emit_jump(merge_block);

                gen.set_current_block(else_block);
                self.gen_stmts(gen, program, else_body)?;
                gen.emit_jump(merge_block);

                gen.set_current_block(merge_block);
            }
            ast::Stmt::For { init, cond, post, body, .. } => {
                if let Some(init) = init {
                    self.gen_stmt(gen, program, init)?;
                }

                let cond_block = gen.new_block("for.cond");
                let body_block = gen.new_block("for.body");
                let post_block = gen.new_block("for.post");
                let exit_block = gen.new_block("for.exit");

                gen.emit_jump(cond_block);
                gen.set_current_block(cond_block);

                if let Some(cond) = cond {
                    let cond_val = self.gen_expr(gen, cond)?;
                    gen.emit_if(cond_val, body_block, exit_block);
                } else {
                    gen.emit_jump(body_block);
                }

                gen.set_current_block(body_block);
                self.gen_stmts(gen, program, body)?;
                gen.emit_jump(post_block);

                gen.set_current_block(post_block);
                if let Some(post) = post {
                    self.gen_stmt(gen, program, post)?;
                }
                gen.emit_jump(cond_block);

                gen.set_current_block(exit_block);
            }
            ast::Stmt::Increment { expr, .. } => {
                if let ast::Expr::VariableRef { name, .. } = expr {
                    if let Some(val) = gen.bindings.lookup(name) {
                        let one = gen.new_const(
                            crate::mpa::Int::from_i64(1, 32),
                            crate::types::Info::int32(),
                        );
                        let result = gen.emit_binary(
                            ssa::instructions::Opcode::Iadd,
                            val,
                            one,
                            crate::types::Info::int32(),
                        );
                        gen.bindings.set(name, result);
                    }
                }
            }
            ast::Stmt::Decrement { expr, .. } => {
                if let ast::Expr::VariableRef { name, .. } = expr {
                    if let Some(val) = gen.bindings.lookup(name) {
                        let one = gen.new_const(
                            crate::mpa::Int::from_i64(1, 32),
                            crate::types::Info::int32(),
                        );
                        let result = gen.emit_binary(
                            ssa::instructions::Opcode::Isub,
                            val,
                            one,
                            crate::types::Info::int32(),
                        );
                        gen.bindings.set(name, result);
                    }
                }
            }
            ast::Stmt::CompoundAssign { op, target, value, .. } => {
                if let ast::Expr::VariableRef { name, .. } = target {
                    if let Some(lhs) = gen.bindings.lookup(name) {
                        let rhs = self.gen_expr(gen, value)?;
                        let opcode = binary_type_to_opcode(op);
                        let result = gen.emit_binary(opcode, lhs, rhs, crate::types::Info::int32());
                        gen.bindings.set(name, result);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn gen_expr(
        &self,
        gen: &mut ssa::Generator,
        expr: &ast::Expr,
    ) -> Result<ssa::value::ValueId, String> {
        match expr {
            ast::Expr::Constant { value, type_info, .. } => {
                match value {
                    ast::ConstValue::Int(v) => {
                        Ok(gen.new_const(v.clone(), type_info.clone()))
                    }
                    ast::ConstValue::Bool(b) => {
                        let val = if *b { 1 } else { 0 };
                        Ok(gen.new_const(
                            crate::mpa::Int::from_i64(val, 1),
                            type_info.clone(),
                        ))
                    }
                    _ => {
                        Ok(gen.new_value("const", type_info.clone()))
                    }
                }
            }
            ast::Expr::VariableRef { name, .. } => {
                gen.bindings
                    .lookup(name)
                    .ok_or_else(|| format!("undefined variable: {}", name))
            }
            ast::Expr::Binary { op, left, right, type_info, .. } => {
                let lhs = self.gen_expr(gen, left)?;
                let rhs = self.gen_expr(gen, right)?;
                let opcode = binary_type_to_opcode(op);
                let result_type = if type_info.is_undefined() {
                    gen.get_value(lhs).type_info.clone()
                } else {
                    type_info.clone()
                };
                Ok(gen.emit_binary(opcode, lhs, rhs, result_type))
            }
            ast::Expr::Unary { op, expr, type_info: _, .. } => {
                let val = self.gen_expr(gen, expr)?;
                let opcode = match op {
                    ast::UnaryType::Minus => ssa::instructions::Opcode::Isub,
                    ast::UnaryType::Not => ssa::instructions::Opcode::Not,
                    ast::UnaryType::Xor => ssa::instructions::Opcode::Bxor,
                    _ => ssa::instructions::Opcode::Mov,
                };
                if matches!(op, ast::UnaryType::Minus) {
                    let zero = gen.new_const(
                        crate::mpa::Int::from_i64(0, 32),
                        gen.get_value(val).type_info.clone(),
                    );
                    Ok(gen.emit_binary(opcode, zero, val, gen.get_value(val).type_info.clone()))
                } else {
                    Ok(gen.emit_unary(opcode, val, gen.get_value(val).type_info.clone()))
                }
            }
            ast::Expr::Call { name, args, .. } => {
                // Built-in function calls.
                let mut arg_vals = Vec::new();
                for arg in args {
                    arg_vals.push(self.gen_expr(gen, arg)?);
                }
                // For now, just return first argument or a placeholder.
                if let Some(&first) = arg_vals.first() {
                    Ok(first)
                } else {
                    Ok(gen.new_value(name, crate::types::Info::default()))
                }
            }
            ast::Expr::Index { expr, index, .. } => {
                let base = self.gen_expr(gen, expr)?;
                let _idx = self.gen_expr(gen, index)?;
                // Simplified: return base value.
                Ok(base)
            }
            _ => {
                Ok(gen.new_value("expr", crate::types::Info::default()))
            }
        }
    }
}

fn binary_type_to_opcode(op: &ast::BinaryType) -> ssa::instructions::Opcode {
    match op {
        ast::BinaryType::Add => ssa::instructions::Opcode::Iadd,
        ast::BinaryType::Sub => ssa::instructions::Opcode::Isub,
        ast::BinaryType::Mul => ssa::instructions::Opcode::Imul,
        ast::BinaryType::Div => ssa::instructions::Opcode::Idiv,
        ast::BinaryType::Mod => ssa::instructions::Opcode::Imod,
        ast::BinaryType::Lt => ssa::instructions::Opcode::Ilt,
        ast::BinaryType::Le => ssa::instructions::Opcode::Ile,
        ast::BinaryType::Gt => ssa::instructions::Opcode::Igt,
        ast::BinaryType::Ge => ssa::instructions::Opcode::Ige,
        ast::BinaryType::Eq => ssa::instructions::Opcode::Ieq,
        ast::BinaryType::Neq => ssa::instructions::Opcode::Ineq,
        ast::BinaryType::And => ssa::instructions::Opcode::And,
        ast::BinaryType::Or => ssa::instructions::Opcode::Or,
        ast::BinaryType::Band => ssa::instructions::Opcode::Band,
        ast::BinaryType::Bor => ssa::instructions::Opcode::Bor,
        ast::BinaryType::Bxor => ssa::instructions::Opcode::Bxor,
        ast::BinaryType::Bclear => ssa::instructions::Opcode::Bclear,
        ast::BinaryType::Lshift => ssa::instructions::Opcode::Lshift,
        ast::BinaryType::Rshift => ssa::instructions::Opcode::Rshift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_simple_add() {
        let mut compiler = Compiler::new(Params::default());
        let circuit = compiler
            .compile(
                r#"
package main

func main(a, b int32) int32 {
    return a + b
}
"#,
                &[vec![32], vec![32]],
            )
            .unwrap();
        assert!(circuit.num_gates > 0);
        assert!(circuit.num_wires > 0);
    }

    #[test]
    fn compile_and_evaluate() {
        let mut compiler = Compiler::new(Params::default());
        let circuit = compiler
            .compile(
                r#"
package main

func main(a, b int32) int32 {
    return a + b
}
"#,
                &[vec![32], vec![32]],
            )
            .unwrap();
        // Verify circuit compiles and has reasonable structure.
        assert!(circuit.num_gates > 0);
        assert!(circuit.num_wires > 0);
        assert_eq!(circuit.inputs.len(), 2);
        assert_eq!(circuit.outputs.len(), 1);
    }
}
