package tries_test

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type HeapTestItem struct {
	value    string
	priority uint64
}

func (t HeapTestItem) Priority() uint64 {
	return t.priority
}

func newHeapTestItem(value string, priority uint64) HeapTestItem {
	return HeapTestItem{value: value, priority: priority}
}

func TestMinHeapAll(t *testing.T) {
	t.Run("Sequential insertion (ascending)", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		for i := 1; i <= count; i++ {
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), uint64(i)))
		}

		items := heap.All()

		assert.Equal(t, count, len(items), "Should have %d items", count)

		priorities := extractPriorities(items)

		isSorted := sort.SliceIsSorted(priorities, func(i, j int) bool {
			return priorities[i] < priorities[j]
		})

		if !isSorted && len(priorities) > 20 {
			t.Logf("First 20 priorities: %v", priorities[:20])
		}

		assert.True(t, isSorted, "Items should be sorted by priority (ascending)")
	})

	t.Run("Sequential insertion (descending)", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		for i := count; i >= 1; i-- {
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), uint64(i)))
		}

		items := heap.All()

		assert.Equal(t, count, len(items), "Should have %d items", count)

		priorities := extractPriorities(items)

		isSorted := sort.SliceIsSorted(priorities, func(i, j int) bool {
			return priorities[i] < priorities[j]
		})

		if !isSorted && len(priorities) > 20 {
			t.Logf("First 20 priorities: %v", priorities[:20])
		}

		assert.True(t, isSorted, "Items should be sorted by priority (ascending)")
	})

	t.Run("Random insertion", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		priorities := make([]uint64, count)
		for i := 0; i < count; i++ {
			priorities[i] = uint64(i + 1)
		}
		rand.Shuffle(count, func(i, j int) {
			priorities[i], priorities[j] = priorities[j], priorities[i]
		})

		for i, p := range priorities {
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), p))
		}

		items := heap.All()

		assert.Equal(t, count, len(items), "Should have %d items", count)

		resultPriorities := extractPriorities(items)

		isSorted := sort.SliceIsSorted(resultPriorities, func(i, j int) bool {
			return resultPriorities[i] < resultPriorities[j]
		})

		if !isSorted && len(resultPriorities) > 20 {
			t.Logf("First 20 priorities: %v", resultPriorities[:20])
		}

		assert.True(t, isSorted, "Items should be sorted by priority (ascending)")
	})

	t.Run("With many duplicates", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		for i := 0; i < count; i++ {
			priority := uint64(i%10) + 1
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), priority))
		}

		items := heap.All()

		assert.Equal(t, count, len(items), "Should have %d items", count)

		priorities := extractPriorities(items)

		isNonDecreasing := true
		for i := 1; i < len(priorities); i++ {
			if priorities[i-1] > priorities[i] {
				isNonDecreasing = false
				t.Logf("Non-decreasing violation at index %d: %d > %d", i, priorities[i-1], priorities[i])
				break
			}
		}

		if !isNonDecreasing && len(priorities) > 20 {
			t.Logf("First 20 priorities: %v", priorities[:20])
		}

		assert.True(t, isNonDecreasing, "Items should be in non-decreasing priority order")

		priorityCounts := make(map[uint64]int)
		for _, p := range priorities {
			priorityCounts[p]++
		}

		for i := uint64(1); i <= 10; i++ {
			assert.Equal(t, count/10, priorityCounts[i], "Should have %d items with priority %d", count/10, i)
		}
	})

	t.Run("After pop operations", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		for i := 0; i < count; i++ {
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), uint64(rand.Intn(10000))))
		}

		poppedItems := make([]HeapTestItem, 0, 200)
		for i := 0; i < 200; i++ {
			item, ok := heap.Pop()
			require.True(t, ok, "Pop should succeed")
			poppedItems = append(poppedItems, item)
		}

		for i := 1; i < len(poppedItems); i++ {
			assert.True(t, poppedItems[i-1].Priority() <= poppedItems[i].Priority(),
				"Popped items should be in ascending order: %d <= %d",
				poppedItems[i-1].Priority(), poppedItems[i].Priority())
		}

		items := heap.All()

		assert.Equal(t, count-200, len(items), "Should have %d items after popping", count-200)

		priorities := extractPriorities(items)

		isSorted := sort.SliceIsSorted(priorities, func(i, j int) bool {
			return priorities[i] < priorities[j]
		})

		if !isSorted && len(priorities) > 20 {
			t.Logf("First 20 priorities: %v", priorities[:20])
		}

		assert.True(t, isSorted, "Items should be sorted by priority (ascending)")

		if len(items) > 0 && len(poppedItems) > 0 {
			assert.True(t, items[0].Priority() >= poppedItems[len(poppedItems)-1].Priority(),
				"Smallest remaining (%d) should be >= largest popped (%d)",
				items[0].Priority(), poppedItems[len(poppedItems)-1].Priority())
		}
	})

	t.Run("Large consecutive priorities", func(t *testing.T) {
		const count = 1000
		heap := tries.NewMinHeap[HeapTestItem]()

		for i := 0; i < count; i++ {
			priority := uint64(1000000 + i)
			heap.Push(newHeapTestItem(fmt.Sprintf("item-%d", i), priority))
		}

		items := heap.All()

		assert.Equal(t, count, len(items), "Should have %d items", count)

		priorities := extractPriorities(items)

		isSorted := sort.SliceIsSorted(priorities, func(i, j int) bool {
			return priorities[i] < priorities[j]
		})

		if !isSorted && len(priorities) > 20 {
			t.Logf("First 20 priorities: %v", priorities[:20])
		}

		assert.True(t, isSorted, "Items should be sorted by priority (ascending)")
	})
}

func extractPriorities(items []HeapTestItem) []uint64 {
	priorities := make([]uint64, len(items))
	for i, item := range items {
		priorities[i] = item.Priority()
	}
	return priorities
}
