package consensus

import (
	"fmt"
	"strings"
	"time"
)

// StateMachineViz provides visualization utilities for the generic state machine
type StateMachineViz[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
] struct {
	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT]
}

// NewStateMachineViz creates a new visualizer for the generic state machine
func NewStateMachineViz[
	StateT Unique,
	VoteT Unique,
	PeerIDT Unique,
	CollectedT Unique,
](
	sm *StateMachine[StateT, VoteT, PeerIDT, CollectedT],
) *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT] {
	return &StateMachineViz[StateT, VoteT, PeerIDT, CollectedT]{sm: sm}
}

// GenerateMermaidDiagram generates a Mermaid diagram of the state machine
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) GenerateMermaidDiagram() string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("stateDiagram-v2\n")
	sb.WriteString("    [*] --> Stopped\n")

	// Define states with descriptions
	// Use CamelCase for state IDs to avoid underscore issues
	stateMap := map[State]string{
		StateStopped:       "Stopped",
		StateStarting:      "Starting",
		StateLoading:       "Loading",
		StateCollecting:    "Collecting",
		StateLivenessCheck: "LivenessCheck",
		StateProving:       "Proving",
		StatePublishing:    "Publishing",
		StateVoting:        "Voting",
		StateFinalizing:    "Finalizing",
		StateVerifying:     "Verifying",
		StateStopping:      "Stopping",
	}

	stateDescriptions := map[State]string{
		StateStopped:       "Engine not running",
		StateStarting:      "Initializing components",
		StateLoading:       "Syncing with network",
		StateCollecting:    "Gathering consensus data",
		StateLivenessCheck: "Checking prover availability",
		StateProving:       "Generating cryptographic proof",
		StatePublishing:    "Broadcasting proposal",
		StateVoting:        "Participating in consensus",
		StateFinalizing:    "Aggregating votes",
		StateVerifying:     "Publishing confirmation",
		StateStopping:      "Cleaning up resources",
	}

	// Add state descriptions
	for state, id := range stateMap {
		desc := stateDescriptions[state]
		sb.WriteString(fmt.Sprintf("    %s : %s\n", id, desc))
	}

	sb.WriteString("\n")

	// Add transitions using mapped state names
	transitions := v.getTransitionList()
	for _, t := range transitions {
		fromID := stateMap[t.From]
		toID := stateMap[t.To]
		if t.Guard != nil {
			sb.WriteString(fmt.Sprintf(
				"    %s --> %s : %s [guarded]\n",
				fromID, toID, t.Event))
		} else {
			sb.WriteString(fmt.Sprintf(
				"    %s --> %s : %s\n",
				fromID, toID, t.Event))
		}
	}

	// Add special annotations using mapped names
	sb.WriteString("\n")
	sb.WriteString("    note right of Proving : Leader only\n")
	sb.WriteString(
		"    note right of LivenessCheck : Divergence point\\nfor leader/non-leader\n",
	)
	sb.WriteString("    note right of Voting : Convergence point\n")

	sb.WriteString("```\n")

	return sb.String()
}

// GenerateDotDiagram generates a Graphviz DOT diagram
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) GenerateDotDiagram() string {
	var sb strings.Builder

	sb.WriteString("digraph ConsensusStateMachine {\n")
	sb.WriteString("    rankdir=TB;\n")
	sb.WriteString("    node [shape=box, style=rounded];\n")
	sb.WriteString("    edge [fontsize=10];\n\n")

	// Define node styles
	sb.WriteString("    // State styles\n")
	sb.WriteString(
		"    Stopped [style=\"rounded,filled\", fillcolor=lightgray];\n",
	)
	sb.WriteString(
		"    Starting [style=\"rounded,filled\", fillcolor=lightyellow];\n",
	)
	sb.WriteString(
		"    Loading [style=\"rounded,filled\", fillcolor=lightyellow];\n",
	)
	sb.WriteString(
		"    Collecting [style=\"rounded,filled\", fillcolor=lightblue];\n",
	)
	sb.WriteString(
		"    LivenessCheck [style=\"rounded,filled\", fillcolor=orange];\n",
	)
	sb.WriteString(
		"    Proving [style=\"rounded,filled\", fillcolor=lightgreen];\n",
	)
	sb.WriteString(
		"    Publishing [style=\"rounded,filled\", fillcolor=lightgreen];\n",
	)
	sb.WriteString(
		"    Voting [style=\"rounded,filled\", fillcolor=lightblue];\n",
	)
	sb.WriteString(
		"    Finalizing [style=\"rounded,filled\", fillcolor=lightblue];\n",
	)
	sb.WriteString(
		"    Verifying [style=\"rounded,filled\", fillcolor=lightblue];\n",
	)
	sb.WriteString(
		"    Stopping [style=\"rounded,filled\", fillcolor=lightcoral];\n\n",
	)

	// Add transitions
	sb.WriteString("    // Transitions\n")
	transitions := v.getTransitionList()
	for _, t := range transitions {
		label := string(t.Event)
		if t.Guard != nil {
			label += " [G]"
		}
		sb.WriteString(fmt.Sprintf(
			"    %s -> %s [label=\"%s\"];\n",
			t.From, t.To, label))
	}

	// Add legend
	sb.WriteString("\n    // Legend\n")
	sb.WriteString("    subgraph cluster_legend {\n")
	sb.WriteString("        label=\"Legend\";\n")
	sb.WriteString("        style=dotted;\n")
	sb.WriteString("        \"[G] = Guarded transition\" [shape=none];\n")
	sb.WriteString("        \"Yellow = Initialization\" [shape=none];\n")
	sb.WriteString("        \"Blue = Consensus flow\" [shape=none];\n")
	sb.WriteString("        \"Green = Leader specific\" [shape=none];\n")
	sb.WriteString("        \"Orange = Decision point\" [shape=none];\n")
	sb.WriteString("    }\n")

	sb.WriteString("}\n")

	return sb.String()
}

// GenerateTransitionTable generates a markdown table of all transitions
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) GenerateTransitionTable() string {
	var sb strings.Builder

	sb.WriteString("| From State | Event | To State | Condition |\n")
	sb.WriteString("|------------|-------|----------|----------|\n")

	transitions := v.getTransitionList()
	for _, t := range transitions {
		condition := "None"
		if t.Guard != nil {
			condition = "Has guard"
		}
		sb.WriteString(fmt.Sprintf(
			"| %s | %s | %s | %s |\n",
			t.From, t.Event, t.To, condition))
	}

	return sb.String()
}

// getTransitionList extracts all transitions from the state machine
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) getTransitionList() []*Transition[StateT, VoteT, PeerIDT, CollectedT] {
	var transitions []*Transition[StateT, VoteT, PeerIDT, CollectedT]

	v.sm.mu.RLock()
	defer v.sm.mu.RUnlock()

	for _, eventMap := range v.sm.transitions {
		for _, transition := range eventMap {
			transitions = append(transitions, transition)
		}
	}

	return transitions
}

// GetStateStats returns statistics about the state machine
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) GetStateStats() string {
	var sb strings.Builder

	sb.WriteString("State Machine Statistics:\n")
	sb.WriteString("========================\n\n")

	v.sm.mu.RLock()
	defer v.sm.mu.RUnlock()

	// Count states and transitions
	stateCount := 0
	transitionCount := 0
	eventCount := make(map[Event]int)

	for _, eventMap := range v.sm.transitions {
		// Only count if we have transitions for this state
		if len(eventMap) > 0 {
			stateCount++
		}
		for event := range eventMap {
			transitionCount++
			eventCount[event]++
		}
	}

	sb.WriteString(fmt.Sprintf("Total States: %d\n", stateCount))
	sb.WriteString(fmt.Sprintf("Total Transitions: %d\n", transitionCount))
	sb.WriteString(fmt.Sprintf("Current State: %s\n", v.sm.machineState))
	sb.WriteString(fmt.Sprintf("Transitions Made: %d\n", v.sm.transitionCount))
	sb.WriteString(
		fmt.Sprintf("Time in Current State: %v\n", v.sm.GetStateTime()),
	)

	// Display current leader info if available
	if len(v.sm.nextProvers) > 0 {
		sb.WriteString("\nNext Leaders:\n")
		for i, leader := range v.sm.nextProvers {
			sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, leader))
		}
	}

	// Display active state info
	if v.sm.activeState != nil {
		sb.WriteString(fmt.Sprintf("\nActive State: %+v\n", v.sm.activeState))
	}

	// Display liveness info
	sb.WriteString(fmt.Sprintf("\nLiveness Checks: %d\n", len(v.sm.liveness)))

	// Display voting info
	sb.WriteString(fmt.Sprintf("Proposals: %d\n", len(v.sm.proposals)))
	sb.WriteString(fmt.Sprintf("Votes: %d\n", len(v.sm.votes)))
	sb.WriteString(fmt.Sprintf("Confirmations: %d\n", len(v.sm.confirmations)))

	sb.WriteString("\nEvent Usage:\n")
	for event, count := range eventCount {
		sb.WriteString(fmt.Sprintf("  %s: %d transitions\n", event, count))
	}

	return sb.String()
}

// GetCurrentStateInfo returns detailed information about the current state
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT]) GetCurrentStateInfo() string {
	v.sm.mu.RLock()
	defer v.sm.mu.RUnlock()

	var sb strings.Builder

	sb.WriteString("Current State Information:\n")
	sb.WriteString("=========================\n\n")
	sb.WriteString(fmt.Sprintf("State: %s\n", v.sm.machineState))
	sb.WriteString(
		fmt.Sprintf("Time in State: %v\n", time.Since(v.sm.stateStartTime)),
	)
	sb.WriteString(fmt.Sprintf("Total Transitions: %d\n", v.sm.transitionCount))

	// State configuration info
	if config, exists := v.sm.stateConfigs[v.sm.machineState]; exists {
		sb.WriteString("\nState Configuration:\n")
		if config.Timeout > 0 {
			sb.WriteString(fmt.Sprintf("  Timeout: %v\n", config.Timeout))
			sb.WriteString(fmt.Sprintf("  Timeout Event: %s\n", config.OnTimeout))
		}
		if config.Behavior != nil {
			sb.WriteString("  Has Behavior: Yes\n")
		}
		if config.OnEnter != nil {
			sb.WriteString("  Has OnEnter Callback: Yes\n")
		}
		if config.OnExit != nil {
			sb.WriteString("  Has OnExit Callback: Yes\n")
		}
	}

	// Available transitions from current state
	sb.WriteString("\nAvailable Transitions:\n")
	if transitions, exists := v.sm.transitions[v.sm.machineState]; exists {
		for event, transition := range transitions {
			guardStr := ""
			if transition.Guard != nil {
				guardStr = " [guarded]"
			}
			sb.WriteString(
				fmt.Sprintf("  %s -> %s%s\n", event, transition.To, guardStr),
			)
		}
	}

	return sb.String()
}

// GenerateEventFlow generates a flow of events that occurred
func (
	v *StateMachineViz[StateT, VoteT, PeerIDT, CollectedT],
) GenerateEventFlow() string {
	var sb strings.Builder

	sb.WriteString("Event Flow:\n")
	sb.WriteString("===========\n\n")

	transitions := v.getTransitionList()
	for i, tr := range transitions {
		sb.WriteString(fmt.Sprintf(
			"%d. %s -> %s [%s]\n",
			i+1, tr.From, tr.To, tr.Event,
		))
	}

	return sb.String()
}
