//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package circuits

// NewUDividerLong creates an unsigned integer division circuit
// computing r=a/b, q=a%b. This function uses Long Division algorithm.
func NewUDividerLong(cc *Compiler, a, b, q, rret []*Wire) error {
	a, b = cc.ZeroPad(a, b)

	r := make([]*Wire, len(a))
	for i := 0; i < len(r); i++ {
		r[i] = cc.ZeroWire()
	}

	for i := len(a) - 1; i >= 0; i-- {
		// r << 1
		for j := len(r) - 1; j > 0; j-- {
			r[j] = r[j-1]
		}
		r[0] = a[i]

		// r-d, overlow: r < d
		diff := make([]*Wire, len(r)+1)
		for j := 0; j < len(diff); j++ {
			diff[j] = cc.Calloc.Wire()
		}
		err := NewSubtractor(cc, r, b, diff)
		if err != nil {
			return err
		}
		if i < len(q) {
			err = NewMUX(cc, diff[len(diff)-1:], []*Wire{cc.ZeroWire()},
				[]*Wire{cc.OneWire()}, q[i:i+1])
			if err != nil {
				return err
			}
		}
		nr := make([]*Wire, len(r))
		for j := 0; j < len(nr); j++ {
			if i == 0 && j < len(rret) {
				nr[j] = rret[j]
			} else {
				nr[j] = cc.Calloc.Wire()
			}
		}

		err = NewMUX(cc, diff[len(diff)-1:], r, diff[:len(diff)-1], nr)
		if err != nil {
			return err
		}
		r = nr
	}

	return nil
}

// NewUDividerRestoring creates an unsigned integer division circuit
// computing r=a/b, q=a%b. This function uses Restoring Division
// algorithm.
func NewUDividerRestoring(cc *Compiler, a, b, q, rret []*Wire) error {
	a, b = cc.ZeroPad(a, b)

	r := make([]*Wire, len(a)*2)
	for i := 0; i < len(r); i++ {
		if i < len(a) {
			r[i] = a[i]
		} else {
			r[i] = cc.ZeroWire()
		}
	}
	d := make([]*Wire, len(b)*2)
	for i := 0; i < len(d); i++ {
		if i < len(b) {
			d[i] = cc.ZeroWire()
		} else {
			d[i] = b[i-len(b)]
		}
	}

	for i := len(a) - 1; i >= 0; i-- {
		// r << 1
		for j := len(r) - 1; j > 0; j-- {
			r[j] = r[j-1]
		}
		r[0] = cc.ZeroWire()

		// r-d, overlow: r < d
		diff := make([]*Wire, len(r)+1)
		for j := 0; j < len(diff); j++ {
			diff[j] = cc.Calloc.Wire()
		}
		err := NewSubtractor(cc, r, d, diff)
		if err != nil {
			return err
		}
		if i < len(q) {
			err = NewMUX(cc, diff[len(diff)-1:], []*Wire{cc.ZeroWire()},
				[]*Wire{cc.OneWire()}, q[i:i+1])
			if err != nil {
				return err
			}
		}
		nr := make([]*Wire, len(r))
		for j := 0; j < len(nr); j++ {
			if i == 0 && j >= len(a) && j-len(a) < len(rret) {
				nr[j] = rret[j-len(a)]
			} else {
				nr[j] = cc.Calloc.Wire()
			}
		}

		err = NewMUX(cc, diff[len(diff)-1:], r, diff[:len(diff)-1], nr)
		if err != nil {
			return err
		}
		r = nr
	}

	return nil
}

// NewUDividerArray creates an unsigned integer division circuit
// computing r=a/b, q=a%b. This function uses Array Divider algorithm.
func NewUDividerArray(cc *Compiler, a, b, q, r []*Wire) error {
	a, b = cc.ZeroPad(a, b)

	rIn := make([]*Wire, len(b)+1)
	rOut := make([]*Wire, len(b)+1)

	// Init bINV.
	bINV := make([]*Wire, len(b))
	for i := 0; i < len(b); i++ {
		bINV[i] = cc.Calloc.Wire()
		cc.INV(b[i], bINV[i])
	}

	// Init for the first row.
	for i := 0; i < len(b); i++ {
		rOut[i] = cc.ZeroWire()
	}

	// Generate matrix.
	for y := 0; y < len(a); y++ {
		// Init rIn.
		rIn[0] = a[len(a)-1-y]
		copy(rIn[1:], rOut)

		// Adders from b{0} to b{n-1}, 0
		cIn := cc.OneWire()
		for x := 0; x < len(b)+1; x++ {
			var bw *Wire
			if x < len(b) {
				bw = bINV[x]
			} else {
				bw = cc.OneWire() // INV(0)
			}
			co := cc.Calloc.Wire()
			ro := cc.Calloc.Wire()
			NewFullAdder(cc, rIn[x], bw, cIn, ro, co)
			rOut[x] = ro
			cIn = co
		}

		// Quotient y.
		if len(a)-1-y < len(q) {
			w := cc.Calloc.Wire()
			cc.INV(cIn, w)
			cc.INV(w, q[len(a)-1-y])
		}

		// MUXes from high to low bit.
		for x := len(b); x >= 0; x-- {
			var ro *Wire
			if y+1 >= len(a) && x < len(r) {
				ro = r[x]
			} else {
				ro = cc.Calloc.Wire()
			}

			err := NewMUX(cc, []*Wire{cIn}, rOut[x:x+1], rIn[x:x+1],
				[]*Wire{ro})
			if err != nil {
				return err
			}
			rOut[x] = ro
		}
	}

	// Set extra quotient bits to zero.
	for y := len(a); y < len(q); y++ {
		q[y] = cc.ZeroWire()
	}

	// Set extra remainder bits to zero.
	for x := len(b); x < len(r); x++ {
		r[x] = cc.ZeroWire()
	}

	return nil
}

// NewUDivider creates an unsigned integer division circuit computing
// r=a/b, q=a%b.
func NewUDivider(cc *Compiler, a, b, q, r []*Wire) error {
	return NewUDividerLong(cc, a, b, q, r)
}

// NewIDivider creates a signed integer division circuit computing
// r=a/b, q=a%b. The function converts negative a and b to positive
// values before doing the divmod with NewUDivider. If a or b was
// negative, the funtion converts the result quotient to negative
// value.
func NewIDivider(cc *Compiler, a, b, q, r []*Wire) error {
	a, b = cc.ZeroPad(a, b)

	zero := []*Wire{cc.ZeroWire()}
	neg0 := cc.ZeroWire()

	// If a is negative, set neg=!neg, a=-a.

	neg1 := cc.Calloc.Wire()
	cc.INV(neg0, neg1)

	a1 := make([]*Wire, len(a))
	for i := 0; i < len(a1); i++ {
		a1[i] = cc.Calloc.Wire()
	}
	err := NewSubtractor(cc, zero, a, a1)
	if err != nil {
		return err
	}

	neg2 := cc.Calloc.Wire()
	err = NewMUX(cc, a[len(a)-1:], []*Wire{neg1}, []*Wire{neg0}, []*Wire{neg2})
	if err != nil {
		return err
	}

	a2 := make([]*Wire, len(a))
	for i := 0; i < len(a2); i++ {
		a2[i] = cc.Calloc.Wire()
	}

	err = NewMUX(cc, a[len(a)-1:], a1, a, a2)
	if err != nil {
		return err
	}

	// If b is negative, set neg=!neg, b=-b.

	neg3 := cc.Calloc.Wire()
	cc.INV(neg2, neg3)

	b1 := make([]*Wire, len(b))
	for i := 0; i < len(b1); i++ {
		b1[i] = cc.Calloc.Wire()
	}
	err = NewSubtractor(cc, zero, b, b1)
	if err != nil {
		return err
	}

	neg4 := cc.Calloc.Wire()
	err = NewMUX(cc, b[len(b)-1:], []*Wire{neg3}, []*Wire{neg2}, []*Wire{neg4})
	if err != nil {
		return err
	}

	b2 := make([]*Wire, len(b))
	for i := 0; i < len(a2); i++ {
		b2[i] = cc.Calloc.Wire()
	}

	err = NewMUX(cc, b[len(b)-1:], b1, b, b2)
	if err != nil {
		return err
	}

	if len(q) == 0 {
		// Modulo operation.
		return NewUDivider(cc, a2, b2, q, r)
	}

	// If neg is set, set q=-q

	q0 := make([]*Wire, len(q))
	for i := 0; i < len(q0); i++ {
		q0[i] = cc.Calloc.Wire()
	}
	err = NewUDivider(cc, a2, b2, q0, r)
	if err != nil {
		return err
	}

	q1 := make([]*Wire, len(q))
	for i := 0; i < len(q1); i++ {
		q1[i] = cc.Calloc.Wire()
	}
	err = NewSubtractor(cc, zero, q0, q1)
	if err != nil {
		return err
	}

	return NewMUX(cc, []*Wire{neg4}, q1, q0, q)
}
