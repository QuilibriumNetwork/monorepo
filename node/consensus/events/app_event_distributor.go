package events

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

// AppEventDistributor processes both GlobalTimeReel and AppTimeReel events
type AppEventDistributor struct {
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	globalEventCh <-chan consensustime.GlobalEvent
	appEventCh    <-chan consensustime.AppEvent
	subscribers   map[string]chan consensus.ControlEvent
	running       bool
	startTime     time.Time
	wg            sync.WaitGroup
}

// NewAppEventDistributor creates a new app event distributor
func NewAppEventDistributor(
	globalEventCh <-chan consensustime.GlobalEvent,
	appEventCh <-chan consensustime.AppEvent,
) *AppEventDistributor {
	return &AppEventDistributor{
		globalEventCh: globalEventCh,
		appEventCh:    appEventCh,
		subscribers:   make(map[string]chan consensus.ControlEvent),
	}
}

// Start begins the event processing loop
func (a *AppEventDistributor) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	a.ctx, a.cancel = context.WithCancel(ctx)
	a.running = true
	a.startTime = time.Now()

	distributorStartsTotal.WithLabelValues("app").Inc()

	a.wg.Add(1)
	go a.processEvents()

	go a.trackUptime()

	return nil
}

// Stop gracefully shuts down the distributor
func (a *AppEventDistributor) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	a.mu.Unlock()

	a.cancel()
	a.wg.Wait()

	a.mu.Lock()
	for _, ch := range a.subscribers {
		close(ch)
	}
	a.subscribers = make(map[string]chan consensus.ControlEvent)
	a.mu.Unlock()

	distributorStopsTotal.WithLabelValues("app").Inc()
	distributorUptime.WithLabelValues("app").Set(0)

	return nil
}

// Subscribe registers a new subscriber
func (a *AppEventDistributor) Subscribe(
	id string,
) <-chan consensus.ControlEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	ch := make(chan consensus.ControlEvent, 100)
	a.subscribers[id] = ch

	subscriptionsTotal.WithLabelValues("app").Inc()
	subscribersCount.WithLabelValues("app").Set(float64(len(a.subscribers)))

	return ch
}

// Publish publishes a new message to all subscribers
func (a *AppEventDistributor) Publish(event consensus.ControlEvent) {
	timer := prometheus.NewTimer(
		eventProcessingDuration.WithLabelValues("control"),
	)

	eventTypeStr := getEventTypeString(event.Type)
	eventsProcessedTotal.WithLabelValues("control", eventTypeStr).Inc()

	a.broadcast(event)

	timer.ObserveDuration()
}

// Unsubscribe removes a subscriber
func (a *AppEventDistributor) Unsubscribe(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ch, exists := a.subscribers[id]; exists {
		delete(a.subscribers, id)
		close(ch)

		unsubscriptionsTotal.WithLabelValues("app").Inc()
		subscribersCount.WithLabelValues("app").Set(float64(len(a.subscribers)))
	}
}

// processEvents is the main event processing loop for both global and app
// events
func (a *AppEventDistributor) processEvents() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			return

		case event, ok := <-a.globalEventCh:
			if !ok {
				return
			}

			a.processGlobalEvent(event)

		case event, ok := <-a.appEventCh:
			if !ok {
				return
			}

			a.processAppEvent(event)
		}
	}
}

// processGlobalEvent processes a global time reel event
func (a *AppEventDistributor) processGlobalEvent(
	event consensustime.GlobalEvent,
) {
	timer := prometheus.NewTimer(eventProcessingDuration.WithLabelValues("app"))
	defer timer.ObserveDuration()

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

	// Update metrics
	eventTypeStr := getEventTypeString(controlEvent.Type)
	eventsProcessedTotal.WithLabelValues("app", eventTypeStr).Inc()

	a.broadcast(controlEvent)
}

// processAppEvent processes an app time reel event
func (a *AppEventDistributor) processAppEvent(event consensustime.AppEvent) {
	timer := prometheus.NewTimer(eventProcessingDuration.WithLabelValues("app"))
	defer timer.ObserveDuration()

	var controlEvent consensus.ControlEvent

	switch event.Type {
	case consensustime.TimeReelEventNewHead:
		controlEvent = consensus.ControlEvent{
			Type: consensus.ControlEventAppNewHead,
			Data: &event,
		}

	case consensustime.TimeReelEventForkDetected:
		controlEvent = consensus.ControlEvent{
			Type: consensus.ControlEventAppFork,
			Data: &event,
		}

	case consensustime.TimeReelEventEquivocationDetected:
		controlEvent = consensus.ControlEvent{
			Type: consensus.ControlEventAppEquivocation,
			Data: &event,
		}
	}

	eventTypeStr := getEventTypeString(controlEvent.Type)
	eventsProcessedTotal.WithLabelValues("app", eventTypeStr).Inc()

	a.broadcast(controlEvent)
}

// broadcast sends a control event to all subscribers
func (a *AppEventDistributor) broadcast(event consensus.ControlEvent) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	timer := prometheus.NewTimer(broadcastDuration.WithLabelValues("app"))
	defer timer.ObserveDuration()

	eventTypeStr := getEventTypeString(event.Type)
	broadcastsTotal.WithLabelValues("app", eventTypeStr).Inc()

	for _, ch := range a.subscribers {
		ch <- event
	}
}

// trackUptime periodically updates the uptime metric
func (a *AppEventDistributor) trackUptime() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.mu.RLock()
			if a.running {
				uptime := time.Since(a.startTime).Seconds()
				distributorUptime.WithLabelValues("app").Set(uptime)
			}
			a.mu.RUnlock()
		}
	}
}
