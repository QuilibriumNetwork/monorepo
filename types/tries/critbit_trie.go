// Modified from https://github.com/tatsushid/go-critbit, MIT Licensed
// Exports fields for seerialization and uses explicit value type
//
// Package critbit implements Crit-Bit tree for byte sequences.
//
// Crit-Bit tree [1] is fast, memory efficient and a variant of PATRICIA trie.
// This implementation can be used for byte sequences if it includes a null
// byte or not. This is based on [2] and extends it to support a null byte in a
// byte sequence.
//
//	[1]: http://cr.yp.to/critbit.html (definition)
//	[2]: https://github.com/agl/critbit (C implementation and document)
package tries

import (
	"bytes"
	"encoding/gob"
)

type NodeType int

func init() {
	gob.Register(&INode{})
	gob.Register(&ENode{})
}

type Value struct {
	Key           []byte
	EarliestFrame uint64
	LatestFrame   uint64
	Count         uint64
}

const (
	Internal NodeType = iota
	External
)

type Node interface {
	kind() NodeType
}

type INode struct {
	Children [2]Node
	Pos      int
	Other    uint8
}

func (n *INode) kind() NodeType { return Internal }

type ENode struct {
	Key   []byte
	Value Value
}

func (n *ENode) kind() NodeType { return External }

// Tree represents a critbit tree.
type Tree struct {
	Root Node
	Size int
}

// New returns an empty tree.
func New() *Tree {
	return &Tree{}
}

// Len returns a number of elements in the tree.
func (t *Tree) Len() int {
	return t.Size
}

func (t *Tree) direction(k []byte, pos int, other uint8) int {
	var c uint8
	if pos < len(k) {
		c = k[pos]
	} else if other == 0xff {
		return 0
	}
	return (1 + int(other|c)) >> 8
}

func (t *Tree) lookup(k []byte) (*ENode, *INode) {
	if t.Root == nil {
		return nil, nil
	}

	var top *INode
	p := t.Root
	for {
		switch n := p.(type) {
		case *ENode:
			return n, top
		case *INode:
			if top == nil || n.Pos < len(k) {
				top = n
			}
			p = n.Children[t.direction(k, n.Pos, n.Other)]
		}
	}
}

// Get searches a given key from the tree. If the key exists in the tree, it
// returns its value and true. If not, it returns nil and false.
func (t *Tree) Get(k []byte) (interface{}, bool) {
	n, _ := t.lookup(k)
	if n != nil && bytes.Equal(k, n.Key) {
		return n.Value, true
	}
	return nil, false
}

func (t *Tree) findFirstDiffByte(k []byte, n *ENode) (pos int, other uint8, match bool) {
	var byt, b byte
	for pos = 0; pos < len(k); pos++ {
		b = k[pos]
		byt = 0
		if pos < len(n.Key) {
			byt = n.Key[pos]
		}
		if byt != b {
			return pos, byt ^ b, false
		}
	}
	if pos < len(n.Key) {
		return pos, n.Key[pos], false
	} else if pos == len(n.Key) {
		return 0, 0, true
	}
	return pos - 1, 0, false
}

func (t *Tree) findInsertPos(k []byte, pos int, other uint8) (*Node, Node) {
	p := &t.Root
	for {
		switch n := (*p).(type) {
		case *ENode:
			return p, n
		case *INode:
			if n.Pos > pos {
				return p, n
			}
			if n.Pos == pos && n.Other > other {
				return p, n
			}
			p = &n.Children[t.direction(k, n.Pos, n.Other)]
		}
	}
}

// Insert adds or updates a given key to the tree and returns its previous
// value and if anything was set or not. If there is the key in the tree, it
// adds the key and the value to the tree and returns nil and true when it
// succeeded while if not, it updates the key's value and returns its previous
// value and true when it succeeded.
func (t *Tree) Insert(k []byte, v Value) (interface{}, bool) {
	key := append([]byte{}, k...)

	n, _ := t.lookup(k)
	if n == nil { // only happens when t.root is nil
		t.Root = &ENode{Key: key, Value: v}
		t.Size++
		return nil, true
	}

	pos, other, match := t.findFirstDiffByte(k, n)
	if match {
		orig := n.Value
		n.Value = v
		return orig, true
	}

	other |= other >> 1
	other |= other >> 2
	other |= other >> 4
	other = ^(other &^ (other >> 1))
	di := t.direction(n.Key, pos, other)

	newn := &INode{Pos: pos, Other: other}
	newn.Children[1-di] = &ENode{Key: key, Value: v}

	p, child := t.findInsertPos(k, pos, other)
	newn.Children[di] = child
	*p = newn

	t.Size++
	return nil, true
}

func (t *Tree) findDeletePos(k []byte) (*Node, *ENode, int) {
	if t.Root == nil {
		return nil, nil, 0
	}

	var di int
	var q *Node
	p := &t.Root
	for {
		switch n := (*p).(type) {
		case *ENode:
			return q, n, di
		case *INode:
			di = t.direction(k, n.Pos, n.Other)
			q = p
			p = &n.Children[di]
		}
	}
}

// Delete removes a given key and its value from the tree. If it succeeded, it
// returns the key's previous value and true while if not, it returns nil and
// false. On an empty tree, it always fails.
func (t *Tree) Delete(k []byte) (interface{}, bool) {
	q, n, di := t.findDeletePos(k)
	if n == nil || !bytes.Equal(k, n.Key) {
		return nil, false
	}
	t.Size--
	if q == nil {
		t.Root = nil
		return n.Value, true
	}
	tmp := (*q).(*INode)
	*q = tmp.Children[1-di]
	return n.Value, true
}

// Clear removes all elements in the tree. If it removes something, it returns
// true while the tree is empty and there is nothing to remove, it returns
// false.
func (t *Tree) Clear() bool {
	if t.Root != nil {
		t.Root = nil
		t.Size = 0
		return true
	}
	return false
}

// Minimum searches a key from the tree in lexicographic order and returns the
// first one and its value. If it found such a key, it also returns true as the
// bool value while if not, it returns false as it.
func (t *Tree) Minimum() ([]byte, interface{}, bool) {
	if t.Root == nil {
		return nil, nil, false
	}

	p := t.Root
	for {
		switch n := p.(type) {
		case *ENode:
			return n.Key, n.Value, true
		case *INode:
			p = n.Children[0]
		}
	}
}

// Maximum searches a key from the tree in lexicographic order and returns the
// last one and its value. If it found such a key, it also returns true as the
// bool value while if not, it returns false as it.
func (t *Tree) Maximum() ([]byte, interface{}, bool) {
	if t.Root == nil {
		return nil, nil, false
	}

	p := t.Root
	for {
		switch n := p.(type) {
		case *ENode:
			return n.Key, n.Value, true
		case *INode:
			p = n.Children[1]
		}
	}
}

func (t *Tree) longestPrefix(p Node, prefix []byte) ([]byte, interface{}, bool) {
	if p == nil {
		return nil, nil, false
	}
	var di int
	var c uint8
	switch n := p.(type) {
	case *ENode:
		if bytes.HasPrefix(prefix, n.Key) {
			return n.Key, n.Value, true
		}
	case *INode:
		c = 0
		if n.Pos < len(prefix) {
			c = prefix[n.Pos]
		}
		di = (1 + int(n.Other|c)) >> 8

		if k, v, ok := t.longestPrefix(n.Children[di], prefix); ok {
			return k, v, ok
		} else if di == 1 {
			return t.longestPrefix(n.Children[0], prefix)
		}
	}
	return nil, nil, false
}

// LongestPrefix searches the longest key which is included in a given key and
// returns the found key and its value. For example, if there are "f", "fo",
// "foobar" in the tree and "foo" is given, it returns "fo". If it found such a
// key, it returns true as the bool value while if not, it returns false as it.
func (t *Tree) LongestPrefix(prefix []byte) ([]byte, interface{}, bool) {
	return t.longestPrefix(t.Root, prefix)
}

// WalkFn is used at walking a tree. It receives a key and its value of each
// elements which a walk function gives. If it returns true, a walk function
// should be terminated at there.
type WalkFn func(k []byte, v interface{}) bool

func (t *Tree) walk(p Node, fn WalkFn) bool {
	if p == nil {
		return false
	}
	switch n := p.(type) {
	case *ENode:
		return fn(n.Key, n.Value)
	case *INode:
		for i := 0; i < 2; i++ {
			if t.walk(n.Children[i], fn) {
				return true
			}
		}
	}
	return false
}

// Walk walks whole the tree and call a given function with each element's key
// and value. If the function returns true, the walk is terminated at there.
func (t *Tree) Walk(fn WalkFn) {
	t.walk(t.Root, fn)
}

// WalkPrefix walks the tree under a given prefix and call a given function
// with each element's key and value. For example, the tree has "f", "fo",
// "foob", "foobar" and "foo" is given, it visits "foob" and "foobar" elements.
// If the function returns true, the walk is terminated at there.
func (t *Tree) WalkPrefix(prefix []byte, fn WalkFn) {
	n, top := t.lookup(prefix)
	if n == nil || !bytes.HasPrefix(n.Key, prefix) {
		return
	}
	wrapper := func(k []byte, v interface{}) bool {
		if bytes.HasPrefix(k, prefix) {
			return fn(k, v)
		}
		return false
	}
	t.walk(top, wrapper)
}

func (t *Tree) walkPath(p Node, path []byte, fn WalkFn) bool {
	if p == nil {
		return false
	}
	var di int
	switch n := p.(type) {
	case *ENode:
		if bytes.HasPrefix(path, n.Key) {
			return fn(n.Key, n.Value)
		}
	case *INode:
		di = t.direction(path, n.Pos, n.Other)
		if di == 1 {
			if t.walkPath(n.Children[0], path, fn) {
				return true
			}
		}
		return t.walkPath(n.Children[di], path, fn)
	}
	return false
}

// WalkPath walks the tree from the root up to a given key and call a given
// function with each element's key and value. For example, the tree has "f",
// "fo", "foob", "foobar" and "foo" is given, it visits "f" and "fo" elements.
// If the function returns true, the walk is terminated at there.
func (t *Tree) WalkPath(path []byte, fn WalkFn) {
	t.walkPath(t.Root, path, fn)
}
