#ifndef QUIL_NATIVE_WITNESS_FAULT_H
#define QUIL_NATIVE_WITNESS_FAULT_H

/* Test-only fault injection for LNP's input-witness check: while nonzero,
 * each check fails as a norm overflow would and consumes one count. Only the
 * fixture bridge's diagnostic entry point sets it; proving leaves it zero. */
extern unsigned int quil_lnp_witness_faults;

static inline int quil_lnp_witness_fault(void) {
  if(!quil_lnp_witness_faults)return 0;
  quil_lnp_witness_faults--;
  return 1;
}

#endif
