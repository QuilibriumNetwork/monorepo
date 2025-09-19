package events

// StartEventData contains data for start events
type StartEventData struct{}

func (StartEventData) ControlEventData() {}

// StopEventData contains data for stop events
type StopEventData struct{}

func (StopEventData) ControlEventData() {}

// HaltEventData contains data for halt events
type HaltEventData struct{}

func (HaltEventData) ControlEventData() {}

// ResumeEventData contains data for resume events
type ResumeEventData struct{}

func (ResumeEventData) ControlEventData() {}
