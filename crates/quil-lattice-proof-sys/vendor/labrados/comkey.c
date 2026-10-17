#include "polx.h"
#include "comkey.h"

size_t comkey_nonce = 0;
polxvec comkey;

/*
  comkey_init ensures that comkey->len is at least as large as len. If this is 
  already the case, comkey is left intact. Otherwise, comkey is expanded to 
  satisfy this condition.

  The parameter len can be set as the length of the vector to be committed, as
  long as the vector is committed all at once, and the extension degree used 
  when committing (typically the least power of 2 greater than or equal to the 
  commitment rank) is at most 32. Otherwise, the caller needs to ensure that the 
  value of len is sufficient for their use of comkey.

  When committing to a vector, the number of polynomials required from comkey 
  is the least multiple of the extension degree that is greater than or equal to 
  the length of the vector. Since extension degrees are powers of 2 and comkey
  is expanded in chunks of 32 polynomials, for extension degrees up to 32 it is 
  enough to call comkey_init with the length of the vector to be committed. If a 
  vector is committed by splitting it in blocks and summing the results from 
  committing to each block, each corresponding block of comkey needs to be a 
  multiple of the extension degree, hence potentially requiring more polynomials
  from comkey.
*/
void comkey_init(size_t len) {
  size_t off;
  __attribute__((aligned(16)))
  uint8_t seed[SEEDLEN] = {};
  polxvec backup, newcomkey;

  if(comkey_nonce && comkey->len >= len)
    return;

  if(comkey_nonce){
    polxvec_init(backup, comkey->len, 1);
    polxvec_copy(backup, comkey);
    polxvec_free(comkey);
  }

  len = (len % 32) ? len + 32 - (len % 32) : len;
  off = 0;
  polxvec_init(comkey, len, 1);

  if(comkey_nonce){
    polxvec_copy(comkey, backup);
    len -= backup->len;
    off += backup->len;
    polxvec_free(backup);
  }

  polxvec_init_subvec2(newcomkey, comkey, off, 1, len);
  /* Match one-shot expansion regardless of allocation/growth history.
   * polxvec_almostuniform advances its nonce by 2^32 per 32 polynomials.
   * comkey_nonce is only the existing initialized-state flag here.
   */
  polxvec_almostuniform(newcomkey, seed, ((uint64_t)(off / 32)) << 32);
  comkey_nonce = 1;
}

void comkey_free(){
  polxvec_free(comkey);
  comkey_nonce = 0;
}