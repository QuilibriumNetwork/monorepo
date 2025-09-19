package events

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// GlobalEventDistributor processes GlobalTimeReel events and distributes
// control events
type GlobalEventDistributor struct {
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	globalEventCh <-chan consensustime.GlobalEvent
	subscribers   map[string]chan consensus.ControlEvent
	running       bool
	startTime     time.Time
	wg            sync.WaitGroup
}

// NewGlobalEventDistributor creates a new global event distributor
func NewGlobalEventDistributor(
	globalEventCh <-chan consensustime.GlobalEvent,
) *GlobalEventDistributor {
	return &GlobalEventDistributor{
		globalEventCh: globalEventCh,
		subscribers:   make(map[string]chan consensus.ControlEvent),
	}
}

// Start begins the event processing loop
func (g *GlobalEventDistributor) Start(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.running {
		return nil
	}

	g.ctx, g.cancel = context.WithCancel(ctx)
	g.running = true
	g.startTime = time.Now()

	distributorStartsTotal.WithLabelValues("global").Inc()

	g.wg.Add(1)
	go g.processEvents()

	go g.trackUptime()

	return nil
}

// Stop gracefully shuts down the distributor
func (g *GlobalEventDistributor) Stop() error {
	g.mu.Lock()
	if !g.running {
		g.mu.Unlock()
		return nil
	}
	g.running = false
	g.mu.Unlock()

	g.cancel()
	g.wg.Wait()

	g.mu.Lock()
	for _, ch := range g.subscribers {
		close(ch)
	}
	g.subscribers = make(map[string]chan consensus.ControlEvent)
	g.mu.Unlock()

	distributorStopsTotal.WithLabelValues("global").Inc()
	distributorUptime.WithLabelValues("global").Set(0)

	return nil
}

// Subscribe registers a new subscriber
func (g *GlobalEventDistributor) Subscribe(
	id string,
) <-chan consensus.ControlEvent {
	g.mu.Lock()
	defer g.mu.Unlock()

	ch := make(chan consensus.ControlEvent, 100)
	g.subscribers[id] = ch

	subscriptionsTotal.WithLabelValues("global").Inc()
	subscribersCount.WithLabelValues("global").Set(float64(len(g.subscribers)))

	return ch
}

// Publish publishes a new message to all subscribers
func (g *GlobalEventDistributor) Publish(event consensus.ControlEvent) {
	timer := prometheus.NewTimer(
		eventProcessingDuration.WithLabelValues("control"),
	)

	eventTypeStr := getEventTypeString(event.Type)
	eventsProcessedTotal.WithLabelValues("control", eventTypeStr).Inc()

	g.broadcast(event)

	timer.ObserveDuration()
}

// Unsubscribe removes a subscriber
func (g *GlobalEventDistributor) Unsubscribe(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if ch, exists := g.subscribers[id]; exists {
		delete(g.subscribers, id)
		close(ch)

		unsubscriptionsTotal.WithLabelValues("global").Inc()
		subscribersCount.WithLabelValues("global").Set(float64(len(g.subscribers)))
	}
}

// processEvents is the main event processing loop
func (g *GlobalEventDistributor) processEvents() {
	defer g.wg.Done()

	for {
		select {
		case <-g.ctx.Done():
			return

		case event, ok := <-g.globalEventCh:
			if !ok {
				return
			}

			timer := prometheus.NewTimer(
				eventProcessingDuration.WithLabelValues("global"),
			)

			var controlEvent consensus.ControlEvent

			switch event.Type {
			case consensustime.TimeReelEventNewHead:
				controlEvent = consensus.ControlEvent{
					Type: consensus.ControlEventGlobalNewHead,
					Data: &event,
				}

			case consensustime.TimeReelEventForkDetected:
				controlEvent = consensus.ControlEvent{
					Type: consensus.ControlEventGlobalFork,
					Data: &event,
				}

			case consensustime.TimeReelEventEquivocationDetected:
				controlEvent = consensus.ControlEvent{
					Type: consensus.ControlEventGlobalEquivocation,
					Data: &event,
				}
			}

			eventTypeStr := getEventTypeString(controlEvent.Type)
			eventsProcessedTotal.WithLabelValues("global", eventTypeStr).Inc()

			g.broadcast(controlEvent)

			timer.ObserveDuration()
		}
	}
}

// broadcast sends a control event to all subscribers
func (g *GlobalEventDistributor) broadcast(event consensus.ControlEvent) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	timer := prometheus.NewTimer(broadcastDuration.WithLabelValues("global"))
	defer timer.ObserveDuration()

	eventTypeStr := getEventTypeString(event.Type)
	broadcastsTotal.WithLabelValues("global", eventTypeStr).Inc()

	for _, ch := range g.subscribers {
		ch <- event
	}
}

// trackUptime periodically updates the uptime metric
func (g *GlobalEventDistributor) trackUptime() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			g.mu.RLock()
			if g.running {
				uptime := time.Since(g.startTime).Seconds()
				distributorUptime.WithLabelValues("global").Set(uptime)
			}
			g.mu.RUnlock()
		}
	}
}
