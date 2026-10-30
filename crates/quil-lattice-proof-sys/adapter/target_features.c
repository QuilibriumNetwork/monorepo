/* The x86 instruction sets beyond baseline x86-64 that the C compiler may
 * emit for this crate, from its target (CFLAGS such as -march; build.rs:
 * QUIL_LATTICE_X86_NATIVE), as comma-terminated is_x86_feature_detected!
 * names. src/cpu.rs checks them against the running CPU and must know every
 * name listed here. Empty on other architectures.
 *
 * RDRAND, RDSEED and SHA are left out: compilers emit their instructions
 * only for explicit intrinsics or inline asm, and this backend has none
 * (src/cpu.rs scans adapter/ and vendor/ to keep it so). Requiring them
 * refused AVX-512 hosts that run the build but report no RDSEED. */
const char *quil_lattice_target_x86_features(void) {
  return ""
#if defined(__x86_64__)
#ifdef __SSE3__
         "sse3,"
#endif
#ifdef __SSSE3__
         "ssse3,"
#endif
#ifdef __SSE4_1__
         "sse4.1,"
#endif
#ifdef __SSE4_2__
         "sse4.2,"
#endif
#ifdef __SSE4A__
         "sse4a,"
#endif
#ifdef __POPCNT__
         "popcnt,"
#endif
#ifdef __LZCNT__
         "lzcnt,"
#endif
#ifdef __BMI__
         "bmi1,"
#endif
#ifdef __BMI2__
         "bmi2,"
#endif
#ifdef __TBM__
         "tbm,"
#endif
#ifdef __MOVBE__
         "movbe,"
#endif
#ifdef __ADX__
         "adx,"
#endif
#ifdef __AES__
         "aes,"
#endif
#ifdef __PCLMUL__
         "pclmulqdq,"
#endif
#ifdef __AVX__
         "avx,"
#endif
#ifdef __F16C__
         "f16c,"
#endif
#ifdef __FMA__
         "fma,"
#endif
#ifdef __AVX2__
         "avx2,"
#endif
#ifdef __AVXVNNI__
         "avxvnni,"
#endif
#ifdef __AVX512F__
         "avx512f,"
#endif
#ifdef __AVX512CD__
         "avx512cd,"
#endif
#ifdef __AVX512BW__
         "avx512bw,"
#endif
#ifdef __AVX512DQ__
         "avx512dq,"
#endif
#ifdef __AVX512VL__
         "avx512vl,"
#endif
#ifdef __AVX512IFMA__
         "avx512ifma,"
#endif
#ifdef __AVX512VBMI__
         "avx512vbmi,"
#endif
#ifdef __AVX512VBMI2__
         "avx512vbmi2,"
#endif
#ifdef __AVX512VNNI__
         "avx512vnni,"
#endif
#ifdef __AVX512BITALG__
         "avx512bitalg,"
#endif
#ifdef __AVX512VPOPCNTDQ__
         "avx512vpopcntdq,"
#endif
#ifdef __AVX512BF16__
         "avx512bf16,"
#endif
#ifdef __AVX512FP16__
         "avx512fp16,"
#endif
#ifdef __AVX512VP2INTERSECT__
         "avx512vp2intersect,"
#endif
#ifdef __GFNI__
         "gfni,"
#endif
#ifdef __VAES__
         "vaes,"
#endif
#ifdef __VPCLMULQDQ__
         "vpclmulqdq,"
#endif
#endif
      ;
}
