//! Diagnostic transport for the fixed public-seed example only. Not a proof
//! codec, transaction format or API for exporting real private assignments.
use quil_lattice_ct::confidential::relation::backend::{
    submission::{RelationSink, StatementSink, SubmissionCounts},
    ScalarRow, SelectionRow,
};
use std::io::{self, Write};

pub struct FixtureSink<W: Write>(pub W);

/// Public-only diagnostic transport for independent verifier reconstruction.
pub struct PublicFixtureSink<W: Write>(pub FixtureSink<W>);

impl<W: Write> StatementSink for PublicFixtureSink<W> {
    type Error = io::Error;
    fn begin(&mut self, modulus: i128, degree: usize, c: SubmissionCounts, n: &[u64]) -> io::Result<()> {
        writeln!(self.0.0, "{{\"kind\":\"begin\",\"format\":\"quil-public-statement-fixture-v2\",\"modulus\":{modulus},\"degree\":{degree},\"counts\":{:?},\"short_normsq\":{n:?}}}", counts(c))
    }
    fn binary_domain(&mut self, index: usize) -> io::Result<()> {
        writeln!(
            self.0 .0,
            "{{\"kind\":\"binary_domain\",\"index\":{index}}}"
        )
    }
    fn short_domain(&mut self, index: usize) -> io::Result<()> {
        writeln!(self.0 .0, "{{\"kind\":\"short_domain\",\"index\":{index}}}")
    }
    fn scalar(&mut self, row: ScalarRow<'_>) -> io::Result<()> {
        self.0.scalar(row)
    }
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> io::Result<()> {
        self.0.linear(terms, rhs)
    }
    fn selection(&mut self, row: SelectionRow) -> io::Result<()> {
        self.0.selection(row)
    }
    fn finish(&mut self, c: SubmissionCounts) -> io::Result<()> {
        self.0.finish(c)
    }
}

fn counts(c: SubmissionCounts) -> [usize; 6] {
    [
        c.original_binary_polynomials,
        c.auxiliary_binary_polynomials,
        c.short_polynomials,
        c.scalar_equations,
        c.linear_equations,
        c.selection_equations,
    ]
}

impl<W: Write> RelationSink for FixtureSink<W> {
    type Error = io::Error;
    fn begin(&mut self, modulus: i128, degree: usize, c: SubmissionCounts, n: &[u64]) -> io::Result<()> {
        writeln!(self.0, "{{\"kind\":\"begin\",\"format\":\"quil-public-fixture-v2\",\"modulus\":{modulus},\"degree\":{degree},\"counts\":{:?},\"short_normsq\":{n:?}}}", counts(c))
    }
    fn binary(&mut self, index: usize, values: &[u8]) -> io::Result<()> {
        writeln!(
            self.0,
            "{{\"kind\":\"binary\",\"index\":{index},\"values\":{values:?}}}"
        )
    }
    fn short(&mut self, index: usize, values: &[i64]) -> io::Result<()> {
        writeln!(self.0, "{{\"kind\":\"short\",\"index\":{index},\"values\":{values:?}}}")
    }
    fn scalar(&mut self, row: ScalarRow<'_>) -> io::Result<()> {
        write!(
            self.0,
            "{{\"kind\":\"scalar\",\"rhs\":{},\"terms\":[",
            row.rhs
        )?;
        for (n, (a, p, i)) in row.terms.iter().enumerate() {
            if n != 0 {
                write!(self.0, ",")?;
            }
            write!(self.0, "[{a},{p},{i}]")?;
        }
        writeln!(self.0, "]}}")
    }
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> io::Result<()> {
        write!(self.0, "{{\"kind\":\"linear\",\"rhs\":{rhs:?},\"terms\":[")?;
        for (n, (p, i)) in terms.iter().enumerate() {
            if n != 0 {
                write!(self.0, ",")?;
            }
            write!(self.0, "[{i},{p:?}]")?;
        }
        writeln!(self.0, "]}}")
    }
    fn selection(&mut self, row: SelectionRow) -> io::Result<()> {
        writeln!(
            self.0,
            "{{\"kind\":\"selection\",\"selector\":{},\"terms\":{:?}}}",
            row.selector, row.terms
        )
    }
    fn finish(&mut self, c: SubmissionCounts) -> io::Result<()> {
        writeln!(self.0, "{{\"kind\":\"finish\",\"counts\":{:?}}}", counts(c))?;
        self.0.flush()
    }
}
