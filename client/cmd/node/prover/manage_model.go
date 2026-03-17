package prover

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// Panel identifiers.
type panel int

const (
	allocationsPanel panel = iota
	availablePanel
)

// pendingAction is used for batch action queues.
type pendingAction struct {
	action string
	filter []byte
	status uint32
}

// Row types for each panel.

type allocationRow struct {
	filter          []byte
	filterKey       string // full hex, used as map key for selection
	filterHex       string // truncated hex, used for display
	status          uint32
	statusName      string
	ring            uint32
	activeProvers   uint32
	shardSize       *big.Int
	estimatedReward *big.Int
	joinFrame       uint64
	confirmFrame    uint64
	leaveFrame      uint64
	lastActiveFrame uint64
}

type shardRow struct {
	filter          []byte
	filterKey       string // full hex, used as map key for selection
	filterHex       string // truncated hex, used for display
	activeProvers   uint32
	ring            uint32
	shardSize       *big.Int
	estimatedReward *big.Int
}

// Messages.

type tickMsg time.Time

type dataRefreshMsg struct {
	nodeInfo  *protobufs.NodeInfoResponse
	shardInfo *protobufs.GetShardInfoResponse
	err       error
}

type actionResultMsg struct {
	action string
	filter string
	err    error
}

type actionPreparedMsg struct {
	action         string
	filter         string
	filtersRaw     [][]byte
	sendFrame      uint64
	originalStatus uint32
	request        *protobufs.MessageRequest
	err            error
}

type actionBroadcastMsg struct {
	action         string
	filter         string
	filtersRaw     [][]byte
	sendFrame      uint64
	originalStatus uint32
	err            error
}

type awaitCheckMsg time.Time

type awaitResultMsg struct {
	action    string
	unchanged bool
	frame     uint64
	err       error
}

type actionConfirmedMsg struct {
	action    string
	filter    string
	newStatus string
	frame     uint64
	timedOut  bool
}

// Key map for help display.

type manageKeyMap struct {
	Up        key.Binding
	Down      key.Binding
	Tab       key.Binding
	Select    key.Binding
	SelectAll key.Binding
	Join      key.Binding
	Leave     key.Binding
	Confirm   key.Binding
	Reject    key.Binding
	Pause     key.Binding
	Resume    key.Binding
	Refresh   key.Binding
	Quit      key.Binding
}

// Constants
const FILTER_WIDTH = 70
const STATUS_WIDTH = 16
const SIZE_WIDTH = 10
const PROVERS_WIDTH = 7
const RING_WIDTH = 5
const REWARD_WIDTH = 20

func newManageKeyMap() manageKeyMap {
	return manageKeyMap{
		Up:        key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:      key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Tab:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch")),
		Select:    key.NewBinding(key.WithKeys("space"), key.WithHelp("spc", "select")),
		SelectAll: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "sel all")),
		Join:      key.NewBinding(key.WithKeys("J"), key.WithHelp("J", "join")),
		Leave:     key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "leave")),
		Confirm:   key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "confirm")),
		Reject:    key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reject")),
		Pause:     key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Resume:    key.NewBinding(key.WithKeys("u"), key.WithHelp("u", "resume")),
		Refresh:   key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "refresh")),
		Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k manageKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Up, k.Down, k.Select, k.SelectAll, k.Join, k.Leave, k.Confirm, k.Reject, k.Pause, k.Resume, k.Refresh, k.Quit}
}

func (k manageKeyMap) FullHelp() [][]key.Binding { return nil }

// Styles.

var (
	mPrimaryColor = lipgloss.Color("#ff0070")
	mDimColor     = lipgloss.Color("#555")
	mTextColor    = lipgloss.Color("#fff")
	mSuccessColor = lipgloss.Color("#00ff00")
	mErrorColor   = lipgloss.Color("#ff0000")
	mHelpColor    = lipgloss.Color("#888")

	mHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(mTextColor).
			Background(mPrimaryColor).
			Padding(0, 1)

	mSelectedStyle = lipgloss.NewStyle().
			Foreground(mTextColor).
			Background(mPrimaryColor)

	mFocusedBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(mPrimaryColor)

	mUnfocusedBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(mDimColor)

	mFooterStyle = lipgloss.NewStyle().
			Foreground(mHelpColor)

	mStatusSuccessStyle = lipgloss.NewStyle().Foreground(mSuccessColor)
	mStatusErrorStyle   = lipgloss.NewStyle().Foreground(mErrorColor)
)

// Model.

type manageModel struct {
	client protobufs.NodeServiceClient

	// Header data.
	peerId           string
	seniority        string
	runningWorkers   uint32
	allocatedWorkers uint32
	lastGlobalHead   uint64
	reachable        bool
	frameNumber      uint64
	difficulty       uint64
	autoManaged      bool

	// Panel data.
	allocations []allocationRow
	available   []shardRow
	allocCursor int
	availCursor int
	focus       panel
	allocOffset int
	availOffset int

	// Multiselect state.
	allocSelected map[string]bool // filter hex → selected
	availSelected map[string]bool // filter hex → selected

	// Batch action queue (processed sequentially).
	actionQueue []pendingAction
	actionTotal int
	actionIndex int

	// Filter input for each panel.
	allocFilter string
	availFilter string

	// Await state for multi-phase action tracking.
	awaitAction         string
	awaitFilters        [][]byte
	awaitOriginalStatus uint32
	awaitSendFrame      uint64
	awaitDeadline       time.Time
	awaitStartTime      time.Time

	// UI.
	width          int
	height         int
	statusMsg      string
	statusIsError  bool
	spinner        spinner.Model
	actionInFlight bool
	help           help.Model
	keyMap         manageKeyMap
}

func newManageModel(client protobufs.NodeServiceClient) manageModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(mPrimaryColor)

	h := help.New()

	cfg := getConfig()
	autoManaged := cfg == nil || cfg.Engine == nil || len(cfg.Engine.DataWorkerFilters) == 0

	return manageModel{
		client:        client,
		keyMap:        newManageKeyMap(),
		spinner:       s,
		help:          h,
		autoManaged:   autoManaged,
		allocSelected: make(map[string]bool),
		availSelected: make(map[string]bool),
	}
}

// Init kicks off the spinner, initial data fetch, and auto-refresh ticker.
func (m manageModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		fetchData(m.client),
		tickEvery(8*time.Second),
	)
}

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func fetchData(client protobufs.NodeServiceClient) tea.Cmd {
	return func() tea.Msg {
		nodeInfo, shardInfo, err := fetchRPCData(client)
		return dataRefreshMsg{
			nodeInfo:  nodeInfo,
			shardInfo: shardInfo,
			err:       err,
		}
	}
}

// Update handles all messages.
func (m manageModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		return m, tea.Batch(
			fetchData(m.client),
			tickEvery(8*time.Second),
		)

	case dataRefreshMsg:
		if msg.err != nil {
			m.statusMsg = msg.err.Error()
			m.statusIsError = true
			return m, nil
		}
		m.processRefreshData(msg.nodeInfo, msg.shardInfo)
		if !m.actionInFlight {
			m.statusMsg = ""
			m.statusIsError = false
		}
		return m, nil

	case actionResultMsg:
		// Join uses this path. Check queue for batch joins.
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("%s failed: %v", msg.action, msg.err)
			m.statusIsError = true
		} else {
			m.statusMsg = fmt.Sprintf("%s sent for %s", msg.action, msg.filter)
			m.statusIsError = false
		}
		if cmd := m.advanceQueue(); cmd != nil {
			return m, cmd
		}
		m.actionInFlight = false
		return m, fetchData(m.client)

	case actionPreparedMsg:
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("%s failed: %v", msg.action, msg.err)
			m.statusIsError = true
			if cmd := m.advanceQueue(); cmd != nil {
				return m, cmd
			}
			m.actionInFlight = false
			return m, nil
		}
		if m.actionTotal > 1 {
			m.statusMsg = fmt.Sprintf("Broadcasting %s (%d/%d)...", msg.action, m.actionIndex, m.actionTotal)
		} else {
			m.statusMsg = fmt.Sprintf("Broadcasting %s to network...", msg.action)
		}
		return m, sendAction(m.client, msg)

	case actionBroadcastMsg:
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("%s broadcast failed: %v", msg.action, msg.err)
			m.statusIsError = true
			if cmd := m.advanceQueue(); cmd != nil {
				return m, cmd
			}
			m.actionInFlight = false
			return m, nil
		}
		// If there are more actions in the queue, skip await and advance.
		if len(m.actionQueue) > 0 {
			m.statusMsg = fmt.Sprintf("%s broadcast (%d/%d)", msg.action, m.actionIndex, m.actionTotal)
			cmd := m.advanceQueue()
			return m, cmd
		}
		now := time.Now()
		m.awaitAction = msg.action
		m.awaitFilters = msg.filtersRaw
		m.awaitOriginalStatus = msg.originalStatus
		m.awaitSendFrame = msg.sendFrame
		m.awaitStartTime = now
		m.awaitDeadline = now.Add(90 * time.Second)
		if m.actionTotal > 1 {
			m.statusMsg = fmt.Sprintf(
				"%d %s(s) broadcast. Awaiting last inclusion (frame %d)...",
				m.actionTotal, msg.action, msg.sendFrame,
			)
		} else {
			m.statusMsg = fmt.Sprintf(
				"%s broadcast (frame %d). Awaiting inclusion...",
				msg.action, msg.sendFrame,
			)
		}
		return m, tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
			return awaitCheckMsg(t)
		})

	case awaitCheckMsg:
		if !m.actionInFlight || m.awaitAction == "" {
			return m, nil
		}
		return m, checkAllocationStatus(
			m.client,
			m.awaitAction,
			m.awaitFilters,
			m.awaitOriginalStatus,
		)

	case awaitResultMsg:
		if !m.actionInFlight || m.awaitAction == "" {
			return m, nil
		}
		if msg.err != nil {
			m.actionInFlight = false
			m.awaitAction = ""
			m.actionQueue = nil
			m.actionTotal = 0
			m.actionIndex = 0
			m.statusMsg = fmt.Sprintf("%s check failed: %v", msg.action, msg.err)
			m.statusIsError = true
			return m, fetchData(m.client)
		}
		if time.Now().After(m.awaitDeadline) {
			m.actionInFlight = false
			m.awaitAction = ""
			m.actionQueue = nil
			m.actionTotal = 0
			m.actionIndex = 0
			m.statusMsg = fmt.Sprintf(
				"%s broadcast at frame %d but not yet confirmed after 90s",
				msg.action, m.awaitSendFrame,
			)
			m.statusIsError = false
			return m, fetchData(m.client)
		}
		elapsed := int(time.Since(m.awaitStartTime).Seconds())
		m.statusMsg = fmt.Sprintf(
			"%s broadcast (frame %d). Awaiting inclusion... (%ds)",
			m.awaitAction, m.awaitSendFrame, elapsed,
		)
		return m, tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
			return awaitCheckMsg(t)
		})

	case actionConfirmedMsg:
		m.actionInFlight = false
		m.awaitAction = ""
		m.actionQueue = nil
		m.actionTotal = 0
		m.actionIndex = 0
		if msg.timedOut {
			m.statusMsg = fmt.Sprintf(
				"%s broadcast but not confirmed after 90s",
				msg.action,
			)
			m.statusIsError = false
		} else {
			m.statusMsg = fmt.Sprintf(
				"%s confirmed at frame %d – status: %s",
				msg.action, msg.frame, msg.newStatus,
			)
			m.statusIsError = false
		}
		return m, fetchData(m.client)

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// selectedAllocRows returns the allocation rows that are currently selected.
// If none are selected, returns just the cursor row.
func (m *manageModel) selectedAllocRows() []allocationRow {
	filtered := m.filteredAllocations()
	if len(filtered) == 0 {
		return nil
	}

	// Collect selected rows in display order.
	var selected []allocationRow
	for _, row := range filtered {
		if m.allocSelected[row.filterKey] {
			selected = append(selected, row)
		}
	}
	if len(selected) > 0 {
		return selected
	}

	// No selections — use cursor row.
	if m.allocCursor < len(filtered) {
		return []allocationRow{filtered[m.allocCursor]}
	}
	return nil
}

// selectedAvailRows returns the available shard rows that are currently selected.
// If none are selected, returns just the cursor row.
func (m *manageModel) selectedAvailRows() []shardRow {
	filtered := m.filteredAvailable()
	if len(filtered) == 0 {
		return nil
	}

	var selected []shardRow
	for _, row := range filtered {
		if m.availSelected[row.filterKey] {
			selected = append(selected, row)
		}
	}
	if len(selected) > 0 {
		return selected
	}

	if m.availCursor < len(filtered) {
		return []shardRow{filtered[m.availCursor]}
	}
	return nil
}

// startMultiFilterAction collects valid filters and sends them in a single message.
// Used for Leave, Confirm, Reject (which support multiple filters per message).
func (m *manageModel) startMultiFilterAction(action string, rows []allocationRow, validStatus func(uint32) bool) (tea.Model, tea.Cmd) {
	var filters [][]byte
	var status uint32
	for _, row := range rows {
		if validStatus(row.status) {
			filters = append(filters, row.filter)
			status = row.status
		}
	}
	if len(filters) == 0 {
		m.statusMsg = fmt.Sprintf("No selected allocations are valid for %s", action)
		m.statusIsError = true
		return m, nil
	}

	m.actionInFlight = true
	m.statusIsError = false
	m.allocSelected = make(map[string]bool)
	m.statusMsg = fmt.Sprintf("Creating %s message for %d allocation(s)...", action, len(filters))

	var cmd tea.Cmd
	switch action {
	case "Leave":
		cmd = doLeave(m.client, filters, status)
	case "Confirm":
		cmd = doConfirm(m.client, filters, status)
	case "Reject":
		cmd = doReject(m.client, filters, status)
	}
	return m, cmd
}

// startBatchAction queues individual actions for operations that only support
// a single filter per message (Pause, Resume).
func (m *manageModel) startBatchAction(action string, rows []allocationRow, validStatus func(uint32) bool) (tea.Model, tea.Cmd) {
	var queue []pendingAction
	for _, row := range rows {
		if validStatus(row.status) {
			queue = append(queue, pendingAction{action: action, filter: row.filter, status: row.status})
		}
	}
	if len(queue) == 0 {
		m.statusMsg = fmt.Sprintf("No selected allocations are valid for %s", action)
		m.statusIsError = true
		return m, nil
	}

	m.actionQueue = queue[1:]
	m.actionTotal = len(queue)
	m.actionIndex = 1
	m.actionInFlight = true
	m.statusIsError = false
	m.allocSelected = make(map[string]bool)

	first := queue[0]
	m.statusMsg = fmt.Sprintf("Creating %s message (%d/%d)...", action, 1, m.actionTotal)

	var cmd tea.Cmd
	switch action {
	case "Pause":
		cmd = doPause(m.client, first.filter, first.status)
	case "Resume":
		cmd = doResume(m.client, first.filter, first.status)
	}
	return m, cmd
}

// advanceQueue starts the next queued action if any remain.
func (m *manageModel) advanceQueue() tea.Cmd {
	if len(m.actionQueue) == 0 {
		return nil
	}

	next := m.actionQueue[0]
	m.actionQueue = m.actionQueue[1:]
	m.actionIndex++
	m.actionInFlight = true
	m.statusIsError = false
	m.statusMsg = fmt.Sprintf("Creating %s message (%d/%d)...", next.action, m.actionIndex, m.actionTotal)

	switch next.action {
	case "Pause":
		return doPause(m.client, next.filter, next.status)
	case "Resume":
		return doResume(m.client, next.filter, next.status)
	}
	return nil
}

func (m manageModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keyMap.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keyMap.Tab):
		if m.focus == allocationsPanel {
			m.focus = availablePanel
		} else {
			m.focus = allocationsPanel
		}

	case key.Matches(msg, m.keyMap.Select):
		if m.focus == allocationsPanel {
			filtered := m.filteredAllocations()
			if m.allocCursor < len(filtered) {
				k := filtered[m.allocCursor].filterKey
				if m.allocSelected[k] {
					delete(m.allocSelected, k)
				} else {
					m.allocSelected[k] = true
				}
				// Advance cursor after toggle.
				if m.allocCursor < len(filtered)-1 {
					m.allocCursor++
				}
			}
		} else {
			filtered := m.filteredAvailable()
			if m.availCursor < len(filtered) {
				k := filtered[m.availCursor].filterKey
				if m.availSelected[k] {
					delete(m.availSelected, k)
				} else {
					m.availSelected[k] = true
				}
				if m.availCursor < len(filtered)-1 {
					m.availCursor++
				}
			}
		}

	case key.Matches(msg, m.keyMap.SelectAll):
		if m.focus == allocationsPanel {
			filtered := m.filteredAllocations()
			allSelected := len(m.allocSelected) == len(filtered) && len(filtered) > 0
			m.allocSelected = make(map[string]bool)
			if !allSelected {
				for _, row := range filtered {
					m.allocSelected[row.filterKey] = true
				}
			}
		} else {
			filtered := m.filteredAvailable()
			allSelected := len(m.availSelected) == len(filtered) && len(filtered) > 0
			m.availSelected = make(map[string]bool)
			if !allSelected {
				for _, row := range filtered {
					m.availSelected[row.filterKey] = true
				}
			}
		}

	case key.Matches(msg, m.keyMap.Up):
		if m.focus == allocationsPanel {
			if m.allocCursor > 0 {
				m.allocCursor--
			}
		} else {
			if m.availCursor > 0 {
				m.availCursor--
			}
		}

	case key.Matches(msg, m.keyMap.Down):
		if m.focus == allocationsPanel {
			filtered := m.filteredAllocations()
			if m.allocCursor < len(filtered)-1 {
				m.allocCursor++
			}
		} else {
			filtered := m.filteredAvailable()
			if m.availCursor < len(filtered)-1 {
				m.availCursor++
			}
		}

	case key.Matches(msg, m.keyMap.Refresh):
		return m, fetchData(m.client)

	case key.Matches(msg, m.keyMap.Join):
		if m.actionInFlight || m.focus != availablePanel {
			return m, nil
		}
		rows := m.selectedAvailRows()
		if len(rows) == 0 {
			return m, nil
		}
		var filters [][]byte
		for _, row := range rows {
			filters = append(filters, row.filter)
		}
		m.actionInFlight = true
		m.statusMsg = fmt.Sprintf("Joining %d shard(s) (VDF may take a while)...", len(filters))
		m.statusIsError = false
		m.availSelected = make(map[string]bool)
		return m, doJoin(m.client, filters)

	case key.Matches(msg, m.keyMap.Leave):
		if m.actionInFlight || m.focus != allocationsPanel {
			return m, nil
		}
		return m.startMultiFilterAction("Leave", m.selectedAllocRows(), func(s uint32) bool { return s == 2 })

	case key.Matches(msg, m.keyMap.Confirm):
		if m.actionInFlight || m.focus != allocationsPanel {
			return m, nil
		}
		return m.startMultiFilterAction("Confirm", m.selectedAllocRows(), func(s uint32) bool { return s == 1 || s == 4 })

	case key.Matches(msg, m.keyMap.Reject):
		if m.actionInFlight || m.focus != allocationsPanel {
			return m, nil
		}
		return m.startMultiFilterAction("Reject", m.selectedAllocRows(), func(s uint32) bool { return s == 1 || s == 4 })

	case key.Matches(msg, m.keyMap.Pause):
		if m.actionInFlight || m.focus != allocationsPanel {
			return m, nil
		}
		return m.startBatchAction("Pause", m.selectedAllocRows(), func(s uint32) bool { return s == 2 })

	case key.Matches(msg, m.keyMap.Resume):
		if m.actionInFlight || m.focus != allocationsPanel {
			return m, nil
		}
		return m.startBatchAction("Resume", m.selectedAllocRows(), func(s uint32) bool { return s == 3 })
	}

	return m, nil
}

// processRefreshData merges NodeInfo + ShardInfo into model state.
func (m *manageModel) processRefreshData(
	nodeInfo *protobufs.NodeInfoResponse,
	shardInfo *protobufs.GetShardInfoResponse,
) {
	// Header.
	m.peerId = nodeInfo.GetPeerId()
	if s := nodeInfo.GetPeerSeniority(); len(s) > 0 {
		m.seniority = new(big.Int).SetBytes(s).String()
	}
	m.runningWorkers = nodeInfo.GetRunningWorkers()
	m.allocatedWorkers = nodeInfo.GetAllocatedWorkers()
	m.lastGlobalHead = nodeInfo.GetLastGlobalHeadFrame()
	m.reachable = nodeInfo.GetReachable()

	if shardInfo != nil {
		m.frameNumber = shardInfo.GetFrameNumber()
		m.difficulty = shardInfo.GetDifficulty()
	}

	// Build a map of shard reward info by filter for enrichment.
	rewardByFilter := make(map[string]*protobufs.ShardRewardInfo)
	allocatedFilters := make(map[string]bool)
	if shardInfo != nil {
		for _, s := range shardInfo.GetShards() {
			key := hex.EncodeToString(s.GetFilter())
			rewardByFilter[key] = s
		}
	}

	// Build allocations from NodeInfo, enriched with ShardInfo.
	allocs := make([]allocationRow, 0, len(nodeInfo.GetShardAllocations()))
	for _, a := range nodeInfo.GetShardAllocations() {
		//skip unknown, rejected and kicked allocations
		if a.GetStatus() == 0 || a.GetStatus() == 5 || a.GetStatus() == 6 {
			continue
		}
		filterHex := hex.EncodeToString(a.GetFilter())
		allocatedFilters[filterHex] = true

		statusName, ok := allocationStatusNames[a.GetStatus()]
		if !ok {
			statusName = fmt.Sprintf("Unknown(%d)", a.GetStatus())
		}

		// For Pending (Joining) and Leaving, annotate with confirmable frame.
		if a.GetStatus() == 1 && a.GetJoinFrameNumber() > 0 {
			confirmAt := a.GetJoinFrameNumber() + 360
			if m.frameNumber >= confirmAt {
				statusName = "Confirm Now"
			} else {
				statusName = fmt.Sprintf("Pending @%d", confirmAt)
			}
		} else if a.GetStatus() == 4 && a.GetLeaveFrameNumber() > 0 {
			confirmAt := a.GetLeaveFrameNumber() + 360
			if m.frameNumber >= confirmAt {
				statusName = "Confirm Now"
			} else {
				statusName = fmt.Sprintf("Leaving @%d", confirmAt)
			}
		}

		row := allocationRow{
			filter:          a.GetFilter(),
			filterKey:       filterHex,
			filterHex:       truncHex(filterHex),
			status:          a.GetStatus(),
			statusName:      statusName,
			joinFrame:       a.GetJoinFrameNumber(),
			confirmFrame:    a.GetJoinConfirmFrameNumber(),
			leaveFrame:      a.GetLeaveFrameNumber(),
			lastActiveFrame: a.GetLastActiveFrameNumber(),
			shardSize:       big.NewInt(0),
			estimatedReward: big.NewInt(0),
		}

		if info, ok := rewardByFilter[filterHex]; ok {
			row.ring = info.GetRing()
			row.activeProvers = info.GetActiveProvers()
			row.shardSize = new(big.Int).SetBytes(info.GetShardSize())
			row.estimatedReward = new(big.Int).SetBytes(info.GetEstimatedReward())
		}

		allocs = append(allocs, row)
	}
	m.allocations = allocs

	// Build available shards: those from ShardInfo where not allocated.
	avail := make([]shardRow, 0)
	if shardInfo != nil {
		for _, s := range shardInfo.GetShards() {
			filterHex := hex.EncodeToString(s.GetFilter())
			if s.GetIsAllocated() || allocatedFilters[filterHex] {
				continue
			}
			avail = append(avail, shardRow{
				filter:          s.GetFilter(),
				filterKey:       filterHex,
				filterHex:       truncHex(filterHex),
				activeProvers:   s.GetActiveProvers(),
				ring:            s.GetRing(),
				shardSize:       new(big.Int).SetBytes(s.GetShardSize()),
				estimatedReward: new(big.Int).SetBytes(s.GetEstimatedReward()),
			})
		}
	}
	// Sort by estimated reward descending.
	sort.Slice(avail, func(i, j int) bool {
		return avail[i].estimatedReward.Cmp(avail[j].estimatedReward) > 0
	})
	m.available = avail

	// Clamp cursors.
	if filtered := m.filteredAllocations(); m.allocCursor >= len(filtered) {
		m.allocCursor = max(0, len(filtered)-1)
	}
	if filtered := m.filteredAvailable(); m.availCursor >= len(filtered) {
		m.availCursor = max(0, len(filtered)-1)
	}
}

func (m manageModel) filteredAllocations() []allocationRow {
	if m.allocFilter == "" {
		return m.allocations
	}
	var out []allocationRow
	for _, a := range m.allocations {
		if strings.Contains(a.filterHex, m.allocFilter) {
			out = append(out, a)
		}
	}
	return out
}

func (m manageModel) filteredAvailable() []shardRow {
	if m.availFilter == "" {
		return m.available
	}
	var out []shardRow
	for _, s := range m.available {
		if strings.Contains(s.filterHex, m.availFilter) {
			out = append(out, s)
		}
	}
	return out
}

// View renders the full TUI.
func (m manageModel) View() tea.View {
	v := tea.NewView(m.renderView())
	v.AltScreen = true
	return v
}

func (m manageModel) renderView() string {
	if m.width < 40 || m.height < 10 {
		return "Terminal too small. Please resize."
	}

	var doc strings.Builder

	// Header bar.
	peerDisplay := m.peerId
	if len(peerDisplay) > 16 {
		peerDisplay = peerDisplay[:8] + ".." + peerDisplay[len(peerDisplay)-6:]
	}
	reachStr := "OK"
	if !m.reachable {
		reachStr = "UNREACHABLE"
	}
	workerMode := "Manual"
	if m.autoManaged {
		workerMode = "Auto"
	}
	header := fmt.Sprintf(
		" Peer ID: %s  Seniority: %s  Workers: %d/%d (%s)  Frame: %d  [%s]",
		peerDisplay,
		m.seniority,
		m.allocatedWorkers,
		m.runningWorkers,
		workerMode,
		m.frameNumber,
		reachStr,
	)
	headerBar := mHeaderStyle.Width(m.width).Render(header)
	doc.WriteString(headerBar)
	doc.WriteString("\n")

	// Calculate panel dimensions.
	innerWidth := m.width - 4 // borders eat 2 chars each side
	if innerWidth < 20 {
		innerWidth = 20
	}
	// Reserve: header(1) + alloc title(1) + alloc border(2) + avail title(1) + avail border(2) + status(1) + help(1) = 9
	panelBudget := m.height - 9
	if panelBudget < 4 {
		panelBudget = 4
	}
	allocHeight := panelBudget / 2
	availHeight := panelBudget - allocHeight

	// Allocations panel.
	filteredAllocs := m.filteredAllocations()
	totalPerFrame := big.NewInt(0)
	for _, a := range filteredAllocs {
		totalPerFrame.Add(totalPerFrame, a.estimatedReward)
	}
	allocTitle := fmt.Sprintf(" Your Allocations (%d) ~%s QUIL/day",
		len(filteredAllocs), formatQUILDaily(totalPerFrame))
	if n := len(m.allocSelected); n > 0 {
		allocTitle += fmt.Sprintf(" [%d selected]", n)
	}
	doc.WriteString(lipgloss.NewStyle().Foreground(mPrimaryColor).Bold(true).Render(allocTitle))
	doc.WriteString("\n")

	allocContent := m.renderAllocationsPanel(innerWidth, allocHeight)
	if m.focus == allocationsPanel {
		doc.WriteString(mFocusedBorderStyle.Width(innerWidth).Height(allocHeight).Render(allocContent))
	} else {
		doc.WriteString(mUnfocusedBorderStyle.Width(innerWidth).Height(allocHeight).Render(allocContent))
	}
	doc.WriteString("\n")

	// Available panel.
	availTitle := fmt.Sprintf(" Available Shards (%d)", len(m.filteredAvailable()))
	if n := len(m.availSelected); n > 0 {
		availTitle += fmt.Sprintf(" [%d selected]", n)
	}
	doc.WriteString(lipgloss.NewStyle().Foreground(mPrimaryColor).Bold(true).Render(availTitle))
	doc.WriteString("\n")

	availContent := m.renderAvailablePanel(innerWidth, availHeight)
	if m.focus == availablePanel {
		doc.WriteString(mFocusedBorderStyle.Width(innerWidth).Height(availHeight).Render(availContent))
	} else {
		doc.WriteString(mUnfocusedBorderStyle.Width(innerWidth).Height(availHeight).Render(availContent))
	}
	doc.WriteString("\n")

	// Status line.
	statusLine := ""
	if m.actionInFlight {
		statusLine = m.spinner.View() + " " + m.statusMsg
	} else if m.statusMsg != "" {
		if m.statusIsError {
			statusLine = mStatusErrorStyle.Render(m.statusMsg)
		} else {
			statusLine = mStatusSuccessStyle.Render(m.statusMsg)
		}
	}

	helpLine := m.help.View(m.keyMap)
	footer := statusLine
	if footer != "" {
		footer += "  "
	}
	footer += helpLine

	doc.WriteString(mFooterStyle.Width(m.width).Render(footer))

	return doc.String()
}

func (m manageModel) renderAllocationsPanel(width, height int) string {
	filtered := m.filteredAllocations()
	if len(filtered) == 0 {
		return "  No allocations"
	}

	hasSelections := len(m.allocSelected) > 0

	// Column header.
	var hdr string
	if hasSelections {
		hdr = fmt.Sprintf("    %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"s %"+strconv.Itoa(RING_WIDTH)+"s %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s %-"+strconv.Itoa(STATUS_WIDTH)+"s",
			"Filter", "Provers", "Ring", "Size", "Reward", "Status")
	} else {
		hdr = fmt.Sprintf("  %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"s %"+strconv.Itoa(RING_WIDTH)+"s %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s %-"+strconv.Itoa(STATUS_WIDTH)+"s",
			"Filter", "Provers", "Ring", "Size", "Reward", "Status")
	}
	lines := []string{lipgloss.NewStyle().Bold(true).Render(hdr)}

	// Compute visible window.
	visibleRows := height - 1 // minus header
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.allocOffset = clampOffset(m.allocOffset, m.allocCursor, visibleRows, len(filtered))

	end := m.allocOffset + visibleRows
	if end > len(filtered) {
		end = len(filtered)
	}

	for i := m.allocOffset; i < end; i++ {
		a := filtered[i]
		var line string
		if hasSelections {
			marker := "[ ]"
			if m.allocSelected[a.filterKey] {
				marker = "[x]"
			}
			line = fmt.Sprintf("%s %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"d %"+strconv.Itoa(RING_WIDTH)+"d %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s %-"+strconv.Itoa(STATUS_WIDTH)+"s",
				marker,
				a.filterHex,
				a.activeProvers,
				a.ring,
				formatStorage(a.shardSize.Uint64()),
				"~"+formatQUIL(a.estimatedReward)+" Q/f",
				a.statusName,
			)
		} else {
			line = fmt.Sprintf("  %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"d %"+strconv.Itoa(RING_WIDTH)+"d %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s %-"+strconv.Itoa(STATUS_WIDTH)+"s",
				a.filterHex,
				a.activeProvers,
				a.ring,
				formatStorage(a.shardSize.Uint64()),
				"~"+formatQUIL(a.estimatedReward)+" Q/f",
				a.statusName,
			)
		}
		if i == m.allocCursor && m.focus == allocationsPanel {
			line = mSelectedStyle.Width(width).Render(line)
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func (m manageModel) renderAvailablePanel(width, height int) string {
	filtered := m.filteredAvailable()
	if len(filtered) == 0 {
		return "  No available shards"
	}

	hasSelections := len(m.availSelected) > 0

	var hdr string
	if hasSelections {
		hdr = fmt.Sprintf("    %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"s %"+strconv.Itoa(RING_WIDTH)+"s %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s",
			"Filter", "Provers", "Ring", "Size", "Reward")
	} else {
		hdr = fmt.Sprintf("  %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"s %"+strconv.Itoa(RING_WIDTH)+"s %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s",
			"Filter", "Provers", "Ring", "Size", "Reward")
	}
	lines := []string{lipgloss.NewStyle().Bold(true).Render(hdr)}

	visibleRows := height - 1
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.availOffset = clampOffset(m.availOffset, m.availCursor, visibleRows, len(filtered))

	end := m.availOffset + visibleRows
	if end > len(filtered) {
		end = len(filtered)
	}

	for i := m.availOffset; i < end; i++ {
		s := filtered[i]
		var line string
		if hasSelections {
			marker := "[ ]"
			if m.availSelected[s.filterKey] {
				marker = "[x]"
			}
			line = fmt.Sprintf("%s %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"d %"+strconv.Itoa(RING_WIDTH)+"d %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s",
				marker,
				s.filterHex,
				s.activeProvers,
				s.ring,
				formatStorage(s.shardSize.Uint64()),
				"~"+formatQUIL(s.estimatedReward)+" Q/f",
			)
		} else {
			line = fmt.Sprintf("  %"+strconv.Itoa(FILTER_WIDTH)+"s %"+strconv.Itoa(PROVERS_WIDTH)+"d %"+strconv.Itoa(RING_WIDTH)+"d %"+strconv.Itoa(SIZE_WIDTH)+"s %"+strconv.Itoa(REWARD_WIDTH)+"s",
				s.filterHex,
				s.activeProvers,
				s.ring,
				formatStorage(s.shardSize.Uint64()),
				"~"+formatQUIL(s.estimatedReward)+" Q/f",
			)
		}
		if i == m.availCursor && m.focus == availablePanel {
			line = mSelectedStyle.Width(width).Render(line)
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

// clampOffset adjusts the scroll offset so cursor is always visible.
func clampOffset(offset, cursor, visibleRows, total int) int {
	if cursor < offset {
		offset = cursor
	}
	if cursor >= offset+visibleRows {
		offset = cursor - visibleRows + 1
	}
	if offset > total-visibleRows {
		offset = total - visibleRows
	}
	if offset < 0 {
		offset = 0
	}
	return offset
}

func truncHex(h string) string {
	if len(h) > FILTER_WIDTH {
		return "..." + h[len(h)-FILTER_WIDTH+4:]
	}
	return h
}

// fetchRPCData calls both GetNodeInfo and GetShardInfo.
func fetchRPCData(client protobufs.NodeServiceClient) (*protobufs.NodeInfoResponse, *protobufs.GetShardInfoResponse, error) {
	nodeInfo, err := client.GetNodeInfo(
		context.Background(),
		&protobufs.GetNodeInfoRequest{},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("GetNodeInfo: %w", err)
	}

	shardInfo, err := client.GetShardInfo(
		context.Background(),
		&protobufs.GetShardInfoRequest{IncludeAll: true},
	)
	if err != nil {
		// Shard info is optional - we can still show allocations.
		return nodeInfo, nil, nil
	}

	return nodeInfo, shardInfo, nil
}
