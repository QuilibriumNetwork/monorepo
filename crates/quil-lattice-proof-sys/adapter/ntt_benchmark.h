/* Explicit diagnostic entry point. Inputs are deterministic public test data.
 * Pin the source and output digest before changing the transform implementation.
 * This checks alias behavior and provides a baseline, not a mathematical proof
 * of transform correctness or an independent reference implementation. */
static double fixture_ntt_seconds(void) {
  struct timespec now;
  if(clock_gettime(CLOCK_MONOTONIC,&now))abort();
  return (double)now.tv_sec+(double)now.tv_nsec/1000000000.0;
}

int quil_fixture_test_signed_mulhi(void) {
  const int16_t factors[]={INT16_MIN,INT16_MIN+1,-16384,-1,0,1,16384,INT16_MAX-1,INT16_MAX};
  int16_t a[32],b[32],out[32];
  for(size_t factor=0;factor<sizeof(factors)/sizeof(factors[0]);factor++) {
    for(int start=INT16_MIN;start<=INT16_MAX;start+=32) {
      for(int lane=0;lane<32;lane++){a[lane]=(int16_t)(start+lane);b[lane]=factors[factor];}
      __m512i product=_mm512_mulhi_epi16(_mm512_loadu_si512(a),_mm512_loadu_si512(b));
      _mm512_storeu_si512(out,product);
      for(int lane=0;lane<32;lane++) {
        uint16_t expected=(uint16_t)((uint32_t)((int32_t)a[lane]*(int32_t)b[lane])>>16);
        if((uint16_t)out[lane]!=expected)return 0;
      }
    }
  }
  return 1;
}

int quil_fixture_test_unsigned_mulhi(void) {
  const uint16_t factors[]={0,1,2,3,16383,16384,32767,32768,65534,65535};
  uint16_t a[32],b[32],out[32];
  for(size_t factor=0;factor<sizeof(factors)/sizeof(factors[0]);factor++) {
    for(uint32_t start=0;start<65536;start+=32) {
      for(size_t lane=0;lane<32;lane++){a[lane]=(uint16_t)(start+lane);b[lane]=factors[factor];}
      __m512i product=_mm512_mulhi_epu16(_mm512_loadu_si512(a),_mm512_loadu_si512(b));
      _mm512_storeu_si512(out,product);
      for(size_t lane=0;lane<32;lane++)
        if(out[lane]!=(uint16_t)(((uint64_t)a[lane]*b[lane])>>16))return 0;
    }
  }
  uint32_t state=UINT32_C(0x8175a391);
  for(size_t batch=0;batch<4096;batch++) {
    for(size_t lane=0;lane<32;lane++) {
      state=state*1664525U+1013904223U;a[lane]=(uint16_t)(state>>16);
      state=state*1664525U+1013904223U;b[lane]=(uint16_t)(state>>16);
    }
    __m512i product=_mm512_mulhi_epu16(_mm512_loadu_si512(a),_mm512_loadu_si512(b));
    _mm512_storeu_si512(out,product);
    for(size_t lane=0;lane<32;lane++)
      if(out[lane]!=(uint16_t)(((uint64_t)a[lane]*b[lane])>>16))return 0;
  }
  return 1;
}

int quil_fixture_ntt_benchmark(size_t rounds,double *seconds,uint8_t *digest) {
  if(!rounds || rounds>32768 || !seconds || !digest)return 0;
  poly inputs[64],outputs[64],inverse,alias;
  shake128incctx hash;
  shake128_inc_init(&hash);
  seconds[0]=seconds[1]=0;
  for(size_t prime=0;prime<K;prime++) {
    uint32_t state=0x12345678U;
    for(size_t i=0;i<64;i++)for(size_t j=0;j<N;j++) {
      state=state*1664525U+1013904223U;
      int value=(int)(state%(2U*(uint32_t)primes[prime]->p+1U))-primes[prime]->p;
      if(i==0)value=0;
      if(i==1)value=primes[prime]->p-1;
      if(i==2)value=1-primes[prime]->p;
      inputs[i]->c[j]=(int16_t)value;
    }
    for(size_t i=0;i<64;i++) {
      poly_ntt(outputs[i],inputs[i],primes[prime]);
      *alias=*inputs[i];poly_ntt(alias,alias,primes[prime]);
      if(memcmp(alias,outputs[i],sizeof(poly)))return 0;
      poly_invntt(inverse,outputs[i],primes[prime]);
      *alias=*outputs[i];poly_invntt(alias,alias,primes[prime]);
      if(memcmp(alias,inverse,sizeof(poly)))return 0;
      // Explicit little-endian output representation, independent of host byte order.
      uint8_t bytes[4*N];
      for(size_t j=0;j<N;j++) {
        uint16_t forward=(uint16_t)outputs[i]->c[j],back=(uint16_t)inverse->c[j];
        bytes[4*j]=forward;bytes[4*j+1]=forward>>8;
        bytes[4*j+2]=back;bytes[4*j+3]=back>>8;
      }
      shake128_inc_absorb(&hash,bytes,sizeof(bytes));
    }
    double start=fixture_ntt_seconds();
    for(size_t i=0;i<rounds;i++)poly_ntt(outputs[i%64],inputs[i%64],primes[prime]);
    seconds[0]+=fixture_ntt_seconds()-start;
    start=fixture_ntt_seconds();
    for(size_t i=0;i<rounds;i++)poly_invntt(alias,outputs[i%64],primes[prime]);
    seconds[1]+=fixture_ntt_seconds()-start;
  }
  shake128_inc_finalize(&hash);shake128_inc_squeeze(digest,32,&hash);
  return 1;
}

/* Exhaust every signed input lane for every configured CRT prime. Integer
 * floor division models the original two shifts, including negative inputs. */
static int32_t fixture_floor_div(int32_t value,int32_t divisor) {
  int32_t quotient=value/divisor;
  return quotient-(value%divisor<0);
}
int quil_fixture_test_poly_reduction(void) {
  poly reduced,added;
  for(size_t k=0;k<K;k++) {
    for(int start=INT16_MIN;start<=INT16_MAX;start+=N) {
      for(size_t i=0;i<N;i++)reduced->c[i]=added->c[i]=(int16_t)(start+(int)i);
      poly_reduce(reduced,primes[k]);
      poly_caddp(added,primes[k]);
      for(size_t i=0;i<N;i++) {
        int32_t input=start+(int)i;
        int32_t high=fixture_floor_div(input*(int32_t)primes[k]->v,65536);
        int32_t quotient=fixture_floor_div(high+1024,2048);
        uint16_t expected=(uint16_t)(input-quotient*(int32_t)primes[k]->p);
        uint16_t expected_add=(uint16_t)(input+(input<0 ? primes[k]->p : 0));
        if((uint16_t)reduced->c[i]!=expected || (uint16_t)added->c[i]!=expected_add)return 0;
      }
    }
  }
  return 1;
}

int quil_fixture_test_poly_scale(void) {
  poly input,output,alias,added,add_alias;
  for(size_t k=0;k<K;k++) {
    int16_t factors[]={INT16_MIN,INT16_MIN+1,-1,0,1,INT16_MAX-1,INT16_MAX,
      (int16_t)-primes[k]->p,primes[k]->p,primes[k]->f};
    for(size_t j=0;j<sizeof(factors)/sizeof(factors[0]);j++) {
      int16_t factor=factors[j];
      int16_t low_factor=(int16_t)(factor*primes[k]->pinv);
      for(int start=INT16_MIN;start<=INT16_MAX;start+=N) {
        for(size_t i=0;i<N;i++) {
          input->c[i]=alias->c[i]=add_alias->c[i]=(int16_t)(start+(int)i);
          added->c[i]=(int16_t)(INT16_MAX-(int)i);
        }
        poly_scale(output,input,factor,primes[k]);
        poly_scale(alias,alias,factor,primes[k]);
        poly_scale_add(added,input,factor,primes[k]);
        poly_scale_add(add_alias,add_alias,factor,primes[k]);
        for(size_t i=0;i<N;i++) {
          int32_t x=input->c[i];
          int16_t low=(int16_t)(x*low_factor);
          int32_t expected=fixture_floor_div(x*factor,65536)
              -fixture_floor_div((int32_t)low*primes[k]->p,65536);
          if((uint16_t)output->c[i]!=(uint16_t)expected
              || output->c[i]!=alias->c[i]
              || (uint16_t)added->c[i]!=(uint16_t)(INT16_MAX-(int)i+expected)
              || (uint16_t)add_alias->c[i]!=(uint16_t)(x+expected))return 0;
        }
      }
    }
  }
  return 1;
}

static int32_t fixture_signed16(int32_t value) {
  uint32_t bits=(uint32_t)value&65535U;
  return bits>=32768U ? (int32_t)bits-65536 : (int32_t)bits;
}
int quil_fixture_test_polz_center(void) {
  const int16_t patterns[]={INT16_MIN,-1,0,1,8191,16383,INT16_MAX};
  polz actual,expected;
  int32_t half[L];
  for(size_t j=0;j<L;j++) {
    half[j]=((uint16_t)modulus->q->limbs[j])>>1;
    if(j<L-1)half[j]=(half[j]+((uint32_t)(uint16_t)modulus->q->limbs[j+1]<<13))&16383;
  }
  for(size_t limb=0;limb<L;limb++)for(size_t pattern=0;pattern<7;pattern++) {
    for(int start=INT16_MIN;start<=INT16_MAX;start+=N) {
      for(size_t i=0;i<N;i++)for(size_t j=0;j<L;j++)
        actual->limbs[j]->c[i]=expected->limbs[j]->c[i]=j==limb ? (int16_t)(start+(int)i) : patterns[pattern];
      for(size_t i=0;i<N;i++) {
        int32_t f=0,carry=0;
        for(size_t j=0;j<L;j++) {
          f=fixture_signed16(half[j]-expected->limbs[j]->c[i]);
          if(j)f=fixture_signed16(f+carry);
          if(j<L-1)carry=fixture_floor_div(f,16384);
        }
        int subtract=f<0;
        for(size_t j=0;j<L;j++) {
          f=fixture_signed16(expected->limbs[j]->c[i]-(subtract ? modulus->q->limbs[j] : 0));
          if(j)f=fixture_signed16(f+carry);
          if(j<L-1){carry=fixture_floor_div(f,16384);f&=16383;}
          expected->limbs[j]->c[i]=(int16_t)f;
        }
      }
      polz_center(actual);
      if(memcmp(actual,expected,sizeof(polz)))return 0;
    }
  }
  return 1;
}
