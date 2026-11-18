#!/usr/bin/env python3
"""Compile/run public parameter boundary checks, without producing a proof."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

base = Path(__file__).resolve().parents[1]
source = r'''
#include <assert.h>
#include <float.h>
#include "private_sampling_params.h"
static void invalid(long double proposed, long double t, int kind) {
    long double cap = 7, sd = proposed, gamma = 9;
    unsigned int scale = 99;
    assert(quil_private_sampling_params(&cap, &scale, &sd, &gamma, t, kind) == 1);
    assert(cap == 7 && scale == 99 && gamma == 9);
    assert(sd == proposed || (isnan(sd) && isnan(proposed)));
}
int main(void) {
    for (int kind = 0; kind <= 1; kind++) {
        for (int i = 0; i <= 26; i++) {
            long double cap = 0, sd = ldexpl((long double)1.55, i), gamma = 0;
            unsigned int scale = 99;
            long double expected = sd;
            assert(quil_private_sampling_params(&cap, &scale, &sd, &gamma, expected / 16, kind) == 0);
            assert(scale == (unsigned)i && sd == expected && gamma == 16);
            assert(cap == expl((kind ? 0 : 14.0L / 16) + 1.0L / 512));
        }
        invalid(0, 1, kind); invalid(-1, 1, kind);
        invalid(NAN, 1, kind); invalid(INFINITY, 1, kind);
        invalid(LDBL_MIN, 1, kind); invalid(LDBL_MAX, 1, kind);
        invalid(ldexpl((long double)1.55, 27), 1, kind);
        invalid(1.55, 0, kind); invalid(1.55, -1, kind);
        invalid(1.55, NAN, kind); invalid(1.55, INFINITY, kind);
        invalid(1.55, LDBL_MAX, kind); /* rejection envelope overflows */
    }
    invalid(1.55, 1, 2);
    /* Standard rounding and upward sign-leak rounding stay distinct. */
    long double cap = 0, sd = 1.55 * 1.1, gamma = 0;
    unsigned int scale = 99;
    assert(!quil_private_sampling_params(&cap, &scale, &sd, &gamma, 1, 0) && scale == 0);
    sd = 1.55 * 1.1;
    assert(!quil_private_sampling_params(&cap, &scale, &sd, &gamma, 1, 1) && scale == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="quil-sampling-params-") as work:
    work = Path(work)
    (work / "check.c").write_text(source)
    compiler = shlex.split(os.environ.get("CC", "clang"))
    subprocess.run(compiler + ["-std=c11", "-O2", "-I", str(base / "vendor/labrados"),
        str(work / "check.c"), "-lm", "-o", str(work / "check")], check=True)
    subprocess.run([str(work / "check")], check=True)
print("PASS private sampling parameter boundaries and supported scales 0..26")
