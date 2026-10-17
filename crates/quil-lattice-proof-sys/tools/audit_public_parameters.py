#!/usr/bin/env python3
"""Inventory default public parameters; this is not a security estimator.

Report exact challenge-support ceilings without generating challenges or proofs.
No computational attack cost or whole-protocol security follows from this report.
"""
import argparse
import ast
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess


def integer_expression(text):
    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp):
            a, b = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Sub):
                return a - b
            if isinstance(node.op, ast.Mult):
                return a * b
            if isinstance(node.op, ast.Div) and a >= 0 and b > 0:
                return a // b  # positive C integer division
        raise ValueError(f"unsupported public parameter expression: {text}")
    return visit(ast.parse(text.strip(), mode="eval").body)


def unique(pattern, text):
    values = re.findall(pattern, text, re.S)
    if len(values) != 1:
        raise ValueError(f"expected exactly one source match for {pattern!r}")
    return int(values[0])


def inventory():
    crate = Path(__file__).resolve().parents[1]
    vendor = crate / "vendor/labrados"
    compiler = shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C preprocessor is required")
    names = ["N", "LOGQ", "QOFF", "TAU1", "TAU2", "T", "LIFTS"]
    source = "".join(f"AUDIT_{name} {name}\n" for name in names)
    output = subprocess.run([compiler, "-E", "-P", "-D__ASSEMBLER__",
        "-include", str(vendor / "data.h"), "-x", "c", "-"], input=source,
        text=True, capture_output=True, check=True).stdout
    values = {}
    for line in output.splitlines():
        if line.startswith("AUDIT_"):
            name, expression = line.split(maxsplit=1)
            values[name.removeprefix("AUDIT_")] = integer_expression(expression)
    if set(values) != set(names):
        raise ValueError("incomplete preprocessor parameter inventory")
    header = (vendor / "data.h").read_text()
    statement = (vendor / "proofsystem.h").read_text()
    sampler = (vendor / "poly.c").read_text()
    transcript = unique(r"uint8_t h\[(\d+)\];", statement)
    seed = unique(r"void polyvec_challenge\([^)]*const uint8_t seed\[(\d+)\]", sampler)
    design_bits = unique(r"#define LIFTS \(\((\d+)\+LOGQ-1\)/LOGQ\)", header)
    n, ones, twos = values["N"], values["TAU1"], values["TAU2"]
    if not (0 <= ones and 0 <= twos and ones + twos <= n):
        raise ValueError("invalid short-challenge weights")
    # Choose disjoint positions of +/-1 and +/-2, then independently their signs.
    support = math.comb(n, ones) * math.comb(n - ones, twos) * 2 ** (ones + twos)
    q = 2 ** values["LOGQ"] - values["QOFF"]
    files = ["data.h", "proofsystem.h", "proofsystem.c", "poly.c", "labrador.c"]
    return {
        "scope": "Default preprocessed public parameters; no build overrides, proof validity or security certification",
        "parameters": values,
        "modulus": q,
        "lift_design_literal_bits": design_bits,
        "formal_field_product_space_bits": values["LIFTS"] * math.log2(q),
        "transcript_state_bytes": transcript,
        "polynomial_challenge_seed_bytes": seed,
        "short_challenge_support_before_norm_filter": str(support),
        "short_challenge_support_bits_upper_bound": math.log2(support),
        "short_challenge_support_below_2_pow_128": support < 2 ** 128,
        "fixed_nonce_seed_support_bits_upper_bound": 8 * seed,
        "sis_root_hermite_factor_expression": re.search(r"#define LOGDELTA ([^\n]+)", header).group(1),
        "limitations": [
            "The operator-norm filter can only reduce the short-challenge support; accepted support and distribution are not measured.",
            "A seed bound is for fixed nonce and sampler arguments, not all protocol transcripts or a computed attack cost.",
            "Formal field-product size does not establish independent sample entropy or soundness: extraction, failure densities and oracle-query losses remain necessary.",
            "The configured root-Hermite factor is not a classical/quantum cost estimate.",
        ],
        "source_sha256": {"vendor/labrados/" + name: hashlib.sha256((vendor / name).read_bytes()).hexdigest() for name in files},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(inventory(), indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end="")
