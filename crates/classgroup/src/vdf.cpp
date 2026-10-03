    /**
    Copyright 2018 Chia Network Inc

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    **/

    /**
    compile:
    g++ -O3 vdf.cpp -lgmpxx -lgmp -lflint -lmpfr -lpthread

    run:
    time sh ./run.sh -0xdc2a335cd2b355c99d3d8d92850122b3d8fe20d0f5360e7aaaecb448960d57bcddfee12a229bbd8d370feda5a17466fc725158ebb78a2a7d37d0a226d89b54434db9c3be9a9bb6ba2c2cd079221d873a17933ceb81a37b0665b9b7e247e8df66bdd45eb15ada12326db01e26c861adf0233666c01dec92bbb547df7369aed3b1fbdff867cfc670511cc270964fbd98e5c55fbe0947ac2b9803acbfd935f3abb8d9be6f938aa4b4cc6203f53c928a979a2f18a1ff501b2587a93e95a428a107545e451f0ac6c7f520a7e99bf77336b1659a2cb3dd1b60e0c6fcfffc05f74cfa763a1d0af7de9994b6e35a9682c4543ae991b3a39839230ef84dae63e88d90f457 2097152

    expected output:
    41925311306490234810413138012137571066190117321086581650264103905212443247266638302300216176280962581197588248081055726676846585755174597863581644696718682501212285820220079934416655823371811162467870568376504352001314014329129123905108990627789940142020588151887088845810858316508373198920329374052520999187
    34852345576682667643688406428836586142306150733999584872507440542733753870999851189854421199460417700803159204522889615033067098373432317909891523566449002340814898056506838421999772358720363985014768637377270846456207130003363936723439348271781377460453326857670664463211470390811155611448465292430048563927
    **/

    #include <cstdint>

    #include <iostream>
    #include <gmpxx.h>
    #include <flint/fmpz.h>
    #define LOG2(X) (63 - __builtin_clzll((X)))
    using namespace std;

    struct form {
    	// y = ax^2 + bxy + y^2
    	mpz_t a;
    	mpz_t b;
    	mpz_t c;
    	// mpz_t d; // discriminant
    };


    const int64_t THRESH = 1UL<<31;
    const int64_t EXP_THRESH = 31;


extern "C" {
    //this normalization is based on Akashnil's entry to the previous round
    inline void normalize(form& f) {
        form f_;
        mpz_inits(f_.a, f_.b, f_.c, NULL);
        mpz_t mu, a2, denom;
    	mpz_inits(mu, a2, denom, NULL);

        mpz_add(mu, f.b, f.c);
        mpz_mul_ui(a2, f.c, 2);
        mpz_fdiv_q(denom, mu, a2);

        mpz_set(f_.a, f.c);

        mpz_mul_ui(a2, denom, 2);
        mpz_neg(f_.b, f.b);
        mpz_addmul(f_.b, f.c, a2);

        mpz_set(f_.c, f.a);
        mpz_submul(f_.c, f.b, denom);
        mpz_mul(denom, denom, denom);
        mpz_addmul(f_.c, f.c, denom);

        mpz_set(f.a, f_.a);
        mpz_set(f.b, f_.b);
        mpz_set(f.c, f_.c);

		// Clear all allocated GMP variables
		mpz_clears(f_.a, f_.b, f_.c, NULL);
		mpz_clears(mu, a2, denom, NULL);
    }

    inline uint64_t signed_shift(uint64_t op, int shift) {
        if (shift > 0) return op << shift;
        if (shift <= -64) return 0;
        return op >> (-shift);
    }

    inline int64_t mpz_get_si_2exp (signed long int *exp, const mpz_t op) {
        uint64_t size = mpz_size(op);
        uint64_t last = mpz_getlimbn(op, size - 1);
        uint64_t ret;
        int lg2 = LOG2(last) + 1;
        *exp = lg2; ret = signed_shift(last, 63 - *exp);
        if (size > 1) {
            *exp += (size-1) * 64;
            uint64_t prev = mpz_getlimbn(op, size - 2);
            ret += signed_shift(prev, -1 - lg2);
        }
        if (mpz_sgn(op) < 0) return - ((int64_t)ret);
        return ret;
    }

    // Test if f is reduced. If it almost is but a, c are swapped,
    // then just swap them to make it reduced.
    inline bool test_reduction(form& f) {
        int a_b = mpz_cmpabs(f.a, f.b);
        int c_b = mpz_cmpabs(f.c, f.b);

        if (a_b < 0 || c_b < 0) return false;

        int a_c = mpz_cmp(f.a, f.c);

        if (a_c > 0) {
            mpz_swap(f.a, f.c); mpz_neg(f.b, f.b);
        }

        if (a_c == 0 && mpz_sgn(f.b) < 0) {
            mpz_neg(f.b, f.b);
        }

        return true;
    }

    // This is based on Akashnil's integer approximation reduce
// This is based on Akashnil's integer approximation reduce
	inline void fast_reduce(form& f) {
		int64_t u, v, w, x, u_, v_, w_, x_;
		int64_t delta, gamma;
		int64_t a, b, c, a_, b_, c_;
		int64_t aa, ab, ac, ba, bb, bc, ca, cb, cc;
		long int a_exp, b_exp, c_exp, max_exp, min_exp;
		mpz_t faa, fab, fac, fba, fbb, fbc, fca, fcb, fcc, a2, mu;

		// Initialize all temporary variables
		mpz_inits(faa, fab, fac, fba, fbb, fbc, fca, fcb, fcc, a2, mu, NULL);

		while (!test_reduction(f)) {
			a = mpz_get_si_2exp(&a_exp, f.a);
			b = mpz_get_si_2exp(&b_exp, f.b);
			c = mpz_get_si_2exp(&c_exp, f.c);

			max_exp = a_exp;
			min_exp = a_exp;

			if (max_exp < b_exp) max_exp = b_exp;
			if (min_exp > b_exp) min_exp = b_exp;

			if (max_exp < c_exp) max_exp = c_exp;
			if (min_exp > c_exp) min_exp = c_exp;

			if (max_exp - min_exp > EXP_THRESH) {
				normalize(f);
				continue;
			}
			max_exp++; // for safety vs overflow

			// Ensure a, b, c are shifted so that a : b : c ratios are same as f.a : f.b : f.c
			// a, b, c will be used as approximations to f.a, f.b, f.c
			a >>= (max_exp - a_exp);
			b >>= (max_exp - b_exp);
			c >>= (max_exp - c_exp);

			u_ = 1;
			v_ = 0;
			w_ = 0;
			x_ = 1;

			// Perform iterative reductions
			do {
				u = u_;
				v = v_;
				w = w_;
				x = x_;

				// Compute delta = floor((b + c) / (2 * c))
				delta = (b >= 0) ? (b + c) / (c << 1) : -(-b + c) / (c << 1);

				a_ = c;
				c_ = c * delta;
				b_ = -b + (c_ << 1);
				gamma = b - c_;
				c_ = a - delta * gamma;

				a = a_;
				b = b_;
				c = c_;

				u_ = v;
				v_ = -u + delta * v;
				w_ = x;
				x_ = -w + delta * x;
			} while ((abs(v_) | abs(x_)) <= THRESH && a > c && c > 0);

			if ((abs(v_) | abs(x_)) <= THRESH) {
				u = u_;
				v = v_;
				w = w_;
				x = x_;
			}

			aa = u * u;
			ab = u * w;
			ac = w * w;
			ba = u * v << 1;
			bb = u * x + v * w;
			bc = w * x << 1;
			ca = v * v;
			cb = v * x;
			cc = x * x;

			// Perform GMP multiplications and additions
			mpz_mul_si(faa, f.a, aa);
			mpz_mul_si(fab, f.b, ab);
			mpz_mul_si(fac, f.c, ac);

			mpz_mul_si(fba, f.a, ba);
			mpz_mul_si(fbb, f.b, bb);
			mpz_mul_si(fbc, f.c, bc);

			mpz_mul_si(fca, f.a, ca);
			mpz_mul_si(fcb, f.b, cb);
			mpz_mul_si(fcc, f.c, cc);

			mpz_add(f.a, faa, fab);
			mpz_add(f.a, f.a, fac);

			mpz_add(f.b, fba, fbb);
			mpz_add(f.b, f.b, fbc);

			mpz_add(f.c, fca, fcb);
			mpz_add(f.c, f.c, fcc);
		}

		// Clear all initialized GMP variables to avoid memory leaks
		mpz_clears(faa, fab, fac, fba, fbb, fbc, fca, fcb, fcc, a2, mu, NULL);
	}

    // https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP
    //based on the implementation from Bulaiden
    inline void gmp_nudupl(form& f, ulong times) {
    mpz_t D, L;
    mpz_t G, dx, dy, By, Dy, x, y, bx, by, ax, ay, q, t, Q1, denom;
    form F;
    fmpz_t fy, fx, fby, fbx, fL;
    	mpz_init(denom);
    	mpz_inits(D, L, NULL);
    	mpz_inits(G, dx, dy, By, Dy, x, y, bx, by, ax, ay, q, t, Q1, denom, NULL);
    	mpz_inits(F.a, F.b, F.c, NULL);

    	fmpz_init(fy);
    	fmpz_init(fx);
    	fmpz_init(fby);
    	fmpz_init(fbx);
    	fmpz_init(fL);
        while(times > 0){
    	    mpz_gcdext(G, y, NULL, f.b, f.a);

    	    mpz_divexact(By, f.a, G);
    	    mpz_divexact(Dy, f.b, G);

    	    mpz_mul(bx, y, f.c);
    	    mpz_mod(bx, bx, By);

    	    mpz_set(by, By);

    	    if (mpz_cmpabs(by, L) <= 0) {
    	    	mpz_mul(dx, bx, Dy);
    	    	mpz_sub(dx, dx, f.c);
    	    	mpz_divexact(dx, dx, By);
    	    	mpz_mul(f.a, by, by);
    	    	mpz_mul(f.c, bx, bx);
    	    	mpz_add(t, bx, by);
    	    	mpz_mul(t, t, t);
    	    	mpz_sub(f.b, f.b, t);
    	    	mpz_add(f.b, f.b, f.a);
    	    	mpz_add(f.b, f.b, f.c);
    	    	mpz_mul(t, G, dx);
    	    	mpz_sub(f.c, f.c, t);
                times--;
    	    	continue;
    	    }

    	    fmpz_set_mpz(fy, y);
    	    fmpz_set_mpz(fx, x);
    	    fmpz_set_mpz(fby, by);
    	    fmpz_set_mpz(fbx, bx);
    	    fmpz_set_mpz(fL, L);

    	    fmpz_xgcd_partial(fy, fx, fby, fbx, fL);

    	    fmpz_get_mpz(y, fy);
    	    fmpz_get_mpz(x, fx);
    	    fmpz_get_mpz(by, fby);
    	    fmpz_get_mpz(bx, fbx);
    	    fmpz_get_mpz(L, fL);

    	    mpz_neg(x, x);
    	    if (mpz_sgn(x) > 0) {
    	    	mpz_neg(y, y);
    	    } else {
    	    	mpz_neg(by, by);
    	    }

    	    mpz_mul(ax, G, x);
    	    mpz_mul(ay, G, y);

    	    mpz_mul(t, Dy, bx);
    	    mpz_submul(t, f.c, x);
    	    mpz_divexact(dx, t, By);
    	    mpz_mul(Q1, y, dx);
    	    mpz_add(dy, Q1, Dy);
    	    mpz_add(f.b, dy, Q1);
    	    mpz_mul(f.b, f.b, G);
    	    mpz_divexact(dy, dy, x);
    	    mpz_mul(f.a, by, by);
    	    mpz_mul(f.c, bx, bx);
    	    mpz_add(t, bx, by);
    	    mpz_submul(f.b, t, t);
    	    mpz_add(f.b, f.b, f.a);
    	    mpz_add(f.b, f.b, f.c);
    	    mpz_submul(f.a, ay, dy);
    	    mpz_submul(f.c, ax, dx);
            times--;
            fast_reduce(f);
        }

    	mpz_clear(denom);
    	mpz_clears(D, L, NULL);
    	mpz_clears(G, dx, dy, By, Dy, x, y, bx, by, ax, ay, q, t, Q1, denom, NULL);
    	mpz_clears(F.a, F.b, F.c, NULL);

    	fmpz_clear(fy);
    	fmpz_clear(fx);
    	fmpz_clear(fby);
    	fmpz_clear(fbx);
    	fmpz_clear(fL);
    }

    void adapted_nudupl(mpz_t& a, mpz_t& b, mpz_t& c, ulong times) {
        //initialise variables
        form newform;
        mpz_inits(newform.a, newform.b, newform.c, NULL);
        mpz_set(newform.a, a);
        mpz_set(newform.b, b);
        mpz_set(newform.c, c);
        gmp_nudupl(newform, times);
        mpz_set(a, newform.a);
        mpz_set(b, newform.b);
        mpz_set(c, newform.c);
        mpz_clears(newform.a, newform.b, newform.c, NULL);
    }


    inline void generator_for_discriminant(form& x, mpz_t& d) {
    	mpz_t denom;
    	mpz_init(denom);
    	mpz_set_ui(x.a, 2);
    	mpz_set_ui(x.b, 1);
    	mpz_mul(x.c, x.b, x.b);
    	mpz_sub(x.c, x.c, d);
    	mpz_mul_ui(denom, x.a, 4);
    	mpz_fdiv_q(x.c, x.c, denom);
    	fast_reduce(x);
    	mpz_clear(denom);
    }
}