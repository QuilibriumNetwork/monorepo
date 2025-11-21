package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"go.uber.org/atomic"
)

// Node describes one component in the graph.
type Node struct {
	Name    string
	Deps    []string // names this node depends on (parents)
	Factory ComponentFactory
	OnError OnError // the handler for this node
}

// Supervisor runs a DAG of nodes with policy-aware error propagation.
type Supervisor struct {
	nodes   map[string]*Node
	parents map[string][]string
	kids    map[string][]string

	// runtime
	cancels map[string]context.CancelFunc
	wg      sync.WaitGroup

	// decision requests from node wrappers
	requests chan decisionReq
	// suppress events that are just the fallout of our own cancels
	suppress sync.Map // name -> struct{}
}

type decisionReq struct {
	from  string
	err   error
	want  ErrorHandlingBehavior // node's own OnError verdict
	reply chan ErrorHandlingBehavior
}

func NewSupervisor(nodes []*Node) (*Supervisor, error) {
	s := &Supervisor{
		nodes:    map[string]*Node{},
		parents:  map[string][]string{},
		kids:     map[string][]string{},
		cancels:  map[string]context.CancelFunc{},
		requests: make(chan decisionReq, 64),
	}
	for _, n := range nodes {
		if _, dup := s.nodes[n.Name]; dup {
			return nil, fmt.Errorf("dup node %q", n.Name)
		}
		s.nodes[n.Name] = n
	}
	// build edges
	for name, n := range s.nodes {
		for _, p := range n.Deps {
			if _, ok := s.nodes[p]; !ok {
				return nil, fmt.Errorf("%s depends on unknown %s", name, p)
			}
			s.parents[name] = append(s.parents[name], p)
			s.kids[p] = append(s.kids[p], name)
		}
	}
	// cycle check via Kahn
	if _, err := topoOrder(s.nodes, s.parents); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Supervisor) Start(ctx context.Context) error {
	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	order, _ := topoOrder(s.nodes, s.parents)

	// start in topo order so deps come up first
	for _, name := range order {
		n := s.nodes[name]
		cctx, cancel := context.WithCancel(ctx)
		s.cancels[name] = cancel
		s.wg.Add(1)
		go func(name string, n *Node, cctx context.Context) {
			defer s.wg.Done()
			// Wrap node's OnError to route decisions through supervisor.
			handler := func(err error) ErrorHandlingBehavior {
				want := ErrorShouldRestart
				if n.OnError != nil {
					want = n.OnError(err)
				}
				// ignore events we ourselves triggered via cancel
				if errors.Is(err, context.Canceled) {
					return ErrorShouldStop
				}
				reply := make(chan ErrorHandlingBehavior, 1)
				s.requests <- decisionReq{
					from:  name,
					err:   err,
					want:  want,
					reply: reply,
				}
				return <-reply
			}
			_ = RunComponent(cctx, n.Factory, handler)
		}(name, n, cctx)
	}

	// coordinator loop
	var shutdownAll atomic.Bool
	for {
		select {
		case <-ctx.Done():
			s.stopAll()
			s.wg.Wait()
			return ctx.Err()

		case req := <-s.requests:
			// Dedup if this node was targeted by a prior cascade
			if _, silenced := s.suppress.Load(req.from); silenced {
				req.reply <- ErrorShouldStop
				continue
			}

			switch req.want {
			case ErrorShouldRestart:
				// no graph action; let RunComponent restart it
				req.reply <- ErrorShouldRestart

			case ErrorShouldStop:
				s.stopSubtree(req.from) // stop node + descendants
				req.reply <- ErrorShouldStop

			case ErrorShouldStopParents:
				s.stopAncestorsAndDesc(req.from)
				req.reply <- ErrorShouldStop

			case ErrorShouldShutdown:
				// Let the child return promptly, then synchronously wait and exit.
				req.reply <- ErrorShouldStop
				// Return the precipitating error so callers can log/act on it.
				return req.err

			case ErrorShouldSpinHalt:
				shutdownAll.Store(true)
				s.stopAll()
				req.reply <- ErrorShouldStop // child returns promptly
				// Block the supervisor until SIGTERM (local wait). Ignore SIGINT.
				term := make(chan os.Signal, 1)
				signal.Notify(term, syscall.SIGTERM)
				<-term
				// After SIGTERM, join everything and return the original error.
				s.wg.Wait()
				return req.err
			}
		}
	}
}

func topoOrder(
	nodes map[string]*Node,
	parents map[string][]string,
) ([]string, error) {
	indeg := map[string]int{}
	for name := range nodes {
		indeg[name] = 0
	}
	for name := range nodes {
		for range parents[name] {
			indeg[name]++
		}
	}
	q := make([]string, 0)
	for n, d := range indeg {
		if d == 0 {
			q = append(q, n)
		}
	}
	var order []string
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		order = append(order, n)
		for _, kid := range kidsOf(n, nodes, parents) {
			indeg[kid]--
			if indeg[kid] == 0 {
				q = append(q, kid)
			}
		}
	}
	if len(order) != len(nodes) {
		return nil, fmt.Errorf("dependency cycle")
	}
	return order, nil
}

func kidsOf(n string, nodes map[string]*Node, parents map[string][]string) []string {
	// build once in NewSupervisor; simplified here:
	var out []string
	for name := range nodes {
		for _, p := range parents[name] {
			if p == n {
				out = append(out, name)
			}
		}
	}
	return out
}

func (s *Supervisor) collectDesc(start string, acc map[string]struct{}) {
	for _, k := range s.kids[start] {
		if _, seen := acc[k]; seen {
			continue
		}
		acc[k] = struct{}{}
		s.collectDesc(k, acc)
	}
}
func (s *Supervisor) collectAnc(start string, acc map[string]struct{}) {
	for _, p := range s.parents[start] {
		if _, seen := acc[p]; seen {
			continue
		}
		acc[p] = struct{}{}
		s.collectAnc(p, acc)
	}
}

func (s *Supervisor) stopAll() {
	for name := range s.cancels {
		s.suppress.Store(name, struct{}{})
	}
	for _, cancel := range s.cancels {
		cancel()
	}
}

func (s *Supervisor) stopSubtree(root string) {
	victims := map[string]struct{}{root: {}}
	s.collectDesc(root, victims)
	for v := range victims {
		s.suppress.Store(v, struct{}{})
	}
	for v := range victims {
		if c := s.cancels[v]; c != nil {
			c()
		}
	}
}

func (s *Supervisor) stopAncestorsAndDesc(root string) {
	victims := map[string]struct{}{root: {}}
	s.collectDesc(root, victims)
	s.collectAnc(root, victims)
	for v := range victims {
		s.suppress.Store(v, struct{}{})
	}
	for v := range victims {
		if c := s.cancels[v]; c != nil {
			c()
		}
	}
}
