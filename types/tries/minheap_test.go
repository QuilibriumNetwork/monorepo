package tries_test

import (
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type TestItem struct {
	value    string
	priority uint64
}

func (t TestItem) Priority() uint64 {
	return t.priority
}

func newTestItem(value string, priority uint64) TestItem {
	return TestItem{value: value, priority: priority}
}

func TestNewMinHeap(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()
	if heap == nil {
		t.Fatal("NewMinHeap returned nil")
	}
	if heap.Size() != 0 {
		t.Errorf("New heap should be empty, got size %d", heap.Size())
	}
}

func TestPush(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()
	heap.Push(newTestItem("test", 1))
	if heap.Size() != 1 {
		t.Errorf("Heap size should be 1 after push, got %d", heap.Size())
	}
	heap.Push(newTestItem("test2", 2))
	if heap.Size() != 2 {
		t.Errorf("Heap size should be 2 after push, got %d", heap.Size())
	}
	heap.Push(newTestItem("test3", 3))
	if heap.Size() != 3 {
		t.Errorf("Heap size should be 3 after push, got %d", heap.Size())
	}
}

func TestPeek(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()

	// Peek empty heap
	_, ok := heap.Peek()
	if ok {
		t.Error("Peek on empty heap should return false")
	}

	// Peek non-empty heap
	heap.Push(newTestItem("test", 1))
	item, ok := heap.Peek()
	if !ok {
		t.Error("Peek on non-empty heap should return true")
	}
	if item.value != "test" || item.priority != 1 {
		t.Errorf("Peek returned unexpected item: %v", item)
	}
}

func TestPop(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()

	// Pop empty heap
	_, ok := heap.Pop()
	if ok {
		t.Error("Pop on empty heap should return false")
	}

	// Pop non-empty heap
	heap.Push(newTestItem("test1", 1))
	heap.Push(newTestItem("test2", 2))
	item, ok := heap.Pop()
	if !ok {
		t.Error("Pop on non-empty heap should return true")
	}
	if item.value != "test1" || item.priority != 1 {
		t.Errorf("Pop returned unexpected item: %v", item)
	}
	if heap.Size() != 1 {
		t.Errorf("Heap size should be 1 after pop, got %d", heap.Size())
	}
}

func TestHeapOrder(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()
	heap.Push(newTestItem("test3", 3))
	heap.Push(newTestItem("test1", 1))
	heap.Push(newTestItem("test2", 2))

	expected := []uint64{1, 2, 3}
	for i, exp := range expected {
		item, ok := heap.Pop()
		if !ok {
			t.Fatalf("Failed to pop item %d", i)
		}
		if item.priority != exp {
			t.Errorf("Item %d: expected priority %d, got %v", i, exp, item.priority)
		}
	}
}

func TestSize(t *testing.T) {
	heap := tries.NewMinHeap[TestItem]()
	sizes := []int{0, 1, 2, 1, 0}

	if heap.Size() != sizes[0] {
		t.Errorf("Initial heap size should be %d, got %d", sizes[0], heap.Size())
	}

	heap.Push(newTestItem("test1", 1))
	if heap.Size() != sizes[1] {
		t.Errorf("Heap size after one push should be %d, got %d", sizes[1], heap.Size())
	}

	heap.Push(newTestItem("test2", 2))
	if heap.Size() != sizes[2] {
		t.Errorf("Heap size after two pushes should be %d, got %d", sizes[2], heap.Size())
	}

	heap.Pop()
	if heap.Size() != sizes[3] {
		t.Errorf("Heap size after pop should be %d, got %d", sizes[3], heap.Size())
	}

	heap.Pop()
	if heap.Size() != sizes[4] {
		t.Errorf("Heap size after second pop should be %d, got %d", sizes[4], heap.Size())
	}
}
