/* Native x86 builds (build.rs: QUIL_LATTICE_X86_NATIVE) take the system
 * intrinsics, which SIMDe then uses; elsewhere SIMDe alone stands in. */
#if defined(__x86_64__) && !defined(SIMDE_NO_NATIVE)
#include_next <immintrin.h>
#endif
#include "../intrinsics.h"
