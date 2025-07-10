package tries

type Item interface {
	Priority() uint64
}

type MinHeap[I Item] struct {
	items []I
}

func NewMinHeap[I Item]() *MinHeap[I] {
	return &MinHeap[I]{items: make([]I, 0)}
}

func (h *MinHeap[I]) Push(item I) {
	h.items = append(h.items, item)
	h.upheap(len(h.items) - 1)
}

func (h *MinHeap[I]) Pop() (I, bool) {
	if len(h.items) == 0 {
		var zero I
		return zero, false
	}
	min := h.items[0]
	lastIdx := len(h.items) - 1
	h.items[0] = h.items[lastIdx]
	h.items = h.items[:lastIdx]
	if len(h.items) > 0 {
		h.downheap(0)
	}
	return min, true
}

func (h *MinHeap[I]) Peek() (I, bool) {
	if len(h.items) == 0 {
		var zero I
		return zero, false
	}
	return h.items[0], true
}

func (h *MinHeap[I]) Size() int {
	return len(h.items)
}

func (h *MinHeap[I]) upheap(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if h.items[i].Priority() >= h.items[parent].Priority() {
			break
		}
		h.items[i], h.items[parent] = h.items[parent], h.items[i]
		i = parent
	}
}

func (h *MinHeap[I]) downheap(i int) {
	for {
		left := 2*i + 1
		right := 2*i + 2
		smallest := i

		if left < len(h.items) &&
			h.items[left].Priority() < h.items[smallest].Priority() {
			smallest = left
		}
		if right < len(h.items) &&
			h.items[right].Priority() < h.items[smallest].Priority() {
			smallest = right
		}

		if smallest == i {
			break
		}

		h.items[i], h.items[smallest] = h.items[smallest], h.items[i]
		i = smallest
	}
}

func (h *MinHeap[I]) All() []I {
	if len(h.items) == 0 {
		return []I{}
	}

	result := make([]I, len(h.items))
	copy(result, h.items)

	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Priority() < result[i].Priority() {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}
