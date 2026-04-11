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

// columnFilter holds the active filter state for a single table column.
type columnFilter struct {
	text   string          // filterColText: substring to match against hex
	values map[string]bool // filterColSelect: selected values (empty = all = no filter)
	expr   string          // filterColNumeric: expression like "> 47" or "1,5,7"
}

func (cf columnFilter) isActive() bool {
	return cf.text != "" || len(cf.values) > 0 || cf.expr != ""
}

type filterColKind int

const (
	filterColText    filterColKind = iota // text substring (Filter column)
	filterColNumeric                      // numeric expression
	filterColSelect                       // text multi-value select
)

// Package-level column name definitions, shared between rendering and filtering.
var (
	allocColNames = []string{
		"Select", "Filter", "Provers", "Ring", "Size [MB]",
		"Shards", "Reward [Q/f]", "Worker", "Status", "Mode",
		"Next Action", "Default Action",
	}
	availColNames = []string{
		"Select", "Filter", "Provers", "Ring", "Size [MB]", "Shards", "Reward [Q/f]",
	}

	// Filterable column indices per panel (matching sort column indices).
	allocFilterableCols = []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	availFilterableCols = []int{1, 2, 3, 4, 5, 6}

	// Filter kind per absolute column index.
	allocFilterColKinds = map[int]filterColKind{
		1: filterColText,
		2: filterColNumeric,
		3: filterColNumeric,
		4: filterColNumeric,
		5: filterColNumeric,
		6: filterColNumeric,
		7: filterColNumeric,
		8: filterColSelect,
		9: filterColSelect,
	}
	availFilterColKinds = map[int]filterColKind{
		1: filterColText,
		2: filterColNumeric,
		3: filterColNumeric,
		4: filterColNumeric,
		5: filterColNumeric,
		6: filterColNumeric,
	}
)

// Row types for each panel.

type allocationRow struct {
	filter          []byte
	filterKey       string // full hex, used as map key for selection
	filterHex       string // full hex, truncated at render time
	status          uint32
	statusName      string
	ring            uint32
	activeProvers   uint32
	shardSize       *big.Int
	dataShards      uint64
	estimatedReward *big.Int
	joinFrame       uint64
	confirmFrame    uint64
	leaveFrame      uint64
	lastActiveFrame uint64
	workerID        int // core_id, -1 if no worker assigned
	nextAction      string
	defaultAction   string
	manuallyManaged bool
}

type shardRow struct {
	filter          []byte
	filterKey       string // full hex, used as map key for selection
	filterHex       string // full hex, truncated at render time
	activeProvers   uint32
	ring            uint32
	shardSize       *big.Int
	dataShards      uint64
	estimatedReward *big.Int
}

// Messages.

type tickMsg time.Time

type dataRefreshMsg struct {
	nodeInfo   *protobufs.NodeInfoResponse
	shardInfo  *protobufs.GetShardInfoResponse
	workerInfo *protobufs.WorkerInfoResponse
	err        error
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

type toggleManualMsg struct {
	coreId   uint32
	newState bool
	err      error
}

type markManualMsg struct {
	workerIDs []uint32
	err       error
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
	Up           key.Binding
	Down         key.Binding
	Tab          key.Binding
	Select       key.Binding
	SelectAll    key.Binding
	Join         key.Binding
	Leave        key.Binding
	Confirm      key.Binding
	Reject       key.Binding
	Pause        key.Binding
	Resume       key.Binding
	ToggleManual key.Binding
	Refresh      key.Binding
	Sort         key.Binding
	Filter       key.Binding
	ColorCoding  key.Binding
	Help         key.Binding
	Quit         key.Binding
}

// Constants
const SELECT_WIDTH = 6
const FILTER_WIDTH = 70
const PROVERS_WIDTH = 7
const RING_WIDTH = 5
const SIZE_WIDTH = 10
const SHARDS_WIDTH = 7
const REWARD_WIDTH = 20
const WORKER_WIDTH = 7
const STATUS_WIDTH = 12
const MODE_WIDTH = 4
const NEXT_ACTION_WIDTH = 30
const DEFAULT_ACTION_WIDTH = 16

// Fixed column widths excluding filter (with inter-column spaces).
const allocFixedWidth = SELECT_WIDTH + PROVERS_WIDTH + RING_WIDTH +
	SIZE_WIDTH + SHARDS_WIDTH + REWARD_WIDTH + WORKER_WIDTH +
	STATUS_WIDTH + MODE_WIDTH + NEXT_ACTION_WIDTH + DEFAULT_ACTION_WIDTH + 11 + 2 + 2 // 11 spaces between 12 columns, 2 external borders and 2-char sort order indicator
const availFixedWidth = SELECT_WIDTH + PROVERS_WIDTH + RING_WIDTH +
	SIZE_WIDTH + SHARDS_WIDTH + REWARD_WIDTH + 6 + 2 + 2 // 6 spaces between 7 columns, 2 external borders and 2-char sort order indicator
const minFilterWidth = 12

const ACTION_FRAME_DELAY = 360

func newManageKeyMap() manageKeyMap {
	return manageKeyMap{
		Up:           key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:         key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Tab:          key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch")),
		Select:       key.NewBinding(key.WithKeys("space"), key.WithHelp("spc", "select")),
		SelectAll:    key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "sel all")),
		Join:         key.NewBinding(key.WithKeys("J"), key.WithHelp("J", "join")),
		Leave:        key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "leave")),
		Confirm:      key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "confirm")),
		Reject:       key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reject")),
		Pause:        key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Resume:       key.NewBinding(key.WithKeys("u"), key.WithHelp("u", "resume")),
		ToggleManual: key.NewBinding(key.WithKeys("M"), key.WithHelp("M", "mode")),
		Refresh:      key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "refresh")),
		Sort:         key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort")),
		Filter:       key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "filter")),
		ColorCoding:  key.NewBinding(key.WithKeys("C"), key.WithHelp("C", "colors")),
		Help:         key.NewBinding(key.WithKeys("h"), key.WithHelp("h", "help")),
		Quit:         key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k manageKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Up, k.Down, k.Select, k.SelectAll, k.Join, k.Leave, k.Confirm, k.Reject, k.Pause, k.Resume, k.ToggleManual, k.Refresh, k.Sort, k.Filter, k.ColorCoding, k.Help, k.Quit}
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
	mFilterColor        = lipgloss.Color("#ffaa00") // amber: active filter indicator

	// Ring gradient: green (ring 0) → yellow-green → yellow → orange → red (ring 4+).
	mRingColor0 = lipgloss.Color("#00ff00")
	mRingColor1 = lipgloss.Color("#88ff00")
	mRingColor2 = lipgloss.Color("#ffff00")
	mRingColor3 = lipgloss.Color("#ff8800")
	mRingColor4 = lipgloss.Color("#ff0000")

	// Status colors.
	mStatusActiveColor  = lipgloss.Color("#00ff00")
	mStatusJoiningColor = lipgloss.Color("#88ff88")
	mStatusLeavingColor = lipgloss.Color("#ff8800")
	mStatusIdleColor    = lipgloss.Color("#ff4444")

	// Mode colors.
	mModeAutoColor   = lipgloss.Color("#00ff00")
	mModeManualColor = lipgloss.Color("#ff8800")
)

func ringStyle(ring uint32) lipgloss.Style {
	switch ring {
	case 0:
		return lipgloss.NewStyle().Foreground(mRingColor0)
	case 1:
		return lipgloss.NewStyle().Foreground(mRingColor1)
	case 2:
		return lipgloss.NewStyle().Foreground(mRingColor2)
	case 3:
		return lipgloss.NewStyle().Foreground(mRingColor3)
	default:
		return lipgloss.NewStyle().Foreground(mRingColor4)
	}
}

func statusStyle(name string) lipgloss.Style {
	switch strings.ToLower(name) {
	case "active":
		return lipgloss.NewStyle().Foreground(mStatusActiveColor)
	case "joining":
		return lipgloss.NewStyle().Foreground(mStatusJoiningColor)
	case "leaving":
		return lipgloss.NewStyle().Foreground(mStatusLeavingColor)
	default: // idle / unknown
		return lipgloss.NewStyle().Foreground(mStatusIdleColor)
	}
}

func modeStyle(mode string) lipgloss.Style {
	if mode == "M" {
		return lipgloss.NewStyle().Foreground(mModeManualColor)
	}
	return lipgloss.NewStyle().Foreground(mModeAutoColor)
}

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

	// Free workers (no filter assigned), refreshed each data fetch.
	freeWorkers []uint32

	// Join worker picker state.
	joinPickerActive   bool
	joinPickerCursor   int
	joinPickerOffset   int
	joinPickerWorkers  []uint32
	joinPickerSelected map[uint32]bool
	joinPickerFilters  [][]byte

	// Await state for multi-phase action tracking.
	awaitAction         string
	awaitFilters        [][]byte
	awaitOriginalStatus uint32
	awaitSendFrame      uint64
	awaitDeadline       time.Time
	awaitStartTime      time.Time

	// Sort state per panel (-1 = no explicit sort).
	allocSortCol int
	allocSortAsc bool
	availSortCol int
	availSortAsc bool

	// Sort selection mode (entered via 's' key).
	sortMode         bool // column selection active
	sortOrderMode    bool // sort order prompt active (sub-state of sortMode)
	sortHighlightCol int  // 0-based column index highlighted in sortMode

	// Per-column filter state (keyed by absolute column index).
	allocColFilters map[int]columnFilter
	availColFilters map[int]columnFilter

	// Filter mode state per panel (entered via 'f' key).
	allocFilterMode         bool
	allocFilterHighlightIdx int // index into allocFilterableCols
	availFilterMode         bool
	availFilterHighlightIdx int // index into availFilterableCols

	// Filter column edit state.
	filterEditActive       bool
	filterEditColIdx       int
	filterEditInput        string // text/numeric input
	filterEditSelectCursor int
	filterEditSelectItems  []string
	filterEditSelectState  map[string]bool

	// UI.
	width          int
	height         int
	statusMsg      string
	statusIsError  bool
	spinner        spinner.Model
	actionInFlight bool
	help           help.Model
	keyMap         manageKeyMap
	showHelp       bool
	colorCoding    bool
}

func newManageModel(client protobufs.NodeServiceClient) manageModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(mPrimaryColor)

	h := help.New()

	return manageModel{
		client:          client,
		keyMap:          newManageKeyMap(),
		spinner:         s,
		help:            h,
		autoManaged:     true, // derived from server data on first refresh
		colorCoding:     true,
		allocSelected:   make(map[string]bool),
		availSelected:   make(map[string]bool),
		allocSortCol:    7, // Worker column, descending
		allocSortAsc:    true,
		availSortCol:    6, // Reward column, descending
		availSortAsc:    false,
		allocColFilters: make(map[int]columnFilter),
		availColFilters: make(map[int]columnFilter),
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
		nodeInfo, shardInfo, workerInfo, err := fetchRPCData(client)
		return dataRefreshMsg{
			nodeInfo:   nodeInfo,
			shardInfo:  shardInfo,
			workerInfo: workerInfo,
			err:        err,
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
		m.processRefreshData(msg.nodeInfo, msg.shardInfo, msg.workerInfo)
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

	case toggleManualMsg:
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("toggle manual mode failed: %v", msg.err)
			m.statusIsError = true
		} else {
			state := "Manual"
			if !msg.newState {
				state = "Auto"
			}
			m.statusMsg = fmt.Sprintf("Worker %d set to %s mode", msg.coreId, state)
			m.statusIsError = false
		}
		return m, fetchData(m.client)

	case markManualMsg:
		// Fire-and-forget: errors here don't block the main action.
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// selectedAllocRows returns the allocation rows that are currently selected.
// If none are selected, returns just the cursor row.
func (m *manageModel) selectedAllocRows() []allocationRow {
	sorted := m.sortedAllocations()
	if len(sorted) == 0 {
		return nil
	}

	// Collect selected rows in display order.
	var selected []allocationRow
	for _, row := range sorted {
		if m.allocSelected[row.filterKey] {
			selected = append(selected, row)
		}
	}
	if len(selected) > 0 {
		return selected
	}

	// No selections — use cursor row.
	if m.allocCursor < len(sorted) {
		return []allocationRow{sorted[m.allocCursor]}
	}
	return nil
}

// selectedAvailRows returns the available shard rows that are currently selected.
// If none are selected, returns just the cursor row.
func (m *manageModel) selectedAvailRows() []shardRow {
	sorted := m.sortedAvailable()
	if len(sorted) == 0 {
		return nil
	}

	var selected []shardRow
	for _, row := range sorted {
		if m.availSelected[row.filterKey] {
			selected = append(selected, row)
		}
	}
	if len(selected) > 0 {
		return selected
	}

	if m.availCursor < len(sorted) {
		return []shardRow{sorted[m.availCursor]}
	}
	return nil
}

// startMultiFilterAction collects valid filters and sends them in a single message.
// Used for Leave, Confirm, Reject (which support multiple filters per message).
// Also marks affected workers as manually managed.
func (m *manageModel) startMultiFilterAction(action string, rows []allocationRow, validStatus func(uint32) bool) (tea.Model, tea.Cmd) {
	var filters [][]byte
	var status uint32
	var workerIDs []uint32
	for _, row := range rows {
		if validStatus(row.status) {
			filters = append(filters, row.filter)
			status = row.status
			if row.workerID >= 0 {
				workerIDs = append(workerIDs, uint32(row.workerID))
			}
		}
	}
	if len(filters) == 0 {
		m.statusMsg = fmt.Sprintf("No selected allocations are valid for %s. Applicable action(s): %s", action, m.applicableActionsLabel())
		m.statusIsError = true
		return m, nil
	}

	m.actionInFlight = true
	m.statusIsError = false
	m.allocSelected = make(map[string]bool)
	m.statusMsg = fmt.Sprintf("Creating %s message for %d allocation(s)...", action, len(filters))

	var cmds []tea.Cmd
	switch action {
	case "Leave":
		cmds = append(cmds, doLeave(m.client, filters, status))
	case "Confirm":
		cmds = append(cmds, doConfirm(m.client, filters, status))
	case "Reject":
		cmds = append(cmds, doReject(m.client, filters, status))
	}
	if len(workerIDs) > 0 {
		cmds = append(cmds, doMarkWorkersManual(m.client, workerIDs))
	}
	return m, tea.Batch(cmds...)
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
		m.statusMsg = fmt.Sprintf("No selected allocations are valid for %s. Applicable action(s): %s", action, m.applicableActionsLabel())
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

// applicableAllocActions returns the set of action names that are valid for the
// current allocation selection (intersection across all selected rows).
// Returns empty when an action is in-flight.
func (m manageModel) applicableAllocActions() map[string]bool {
	if m.actionInFlight {
		return map[string]bool{}
	}

	rows := m.selectedAllocRows()
	if len(rows) == 0 {
		return map[string]bool{}
	}

	actionsForRow := func(row allocationRow) map[string]bool {
		switch row.status {
		case 1:
			// Confirm is only valid once the action window opens (joinFrame+delay)
			// and before it expires (joinFrame+2*delay).
			actions := map[string]bool{"Reject": true}
			if row.joinFrame > 0 {
				actionFrame := row.joinFrame + ACTION_FRAME_DELAY
				expiryFrame := row.joinFrame + ACTION_FRAME_DELAY*2
				if m.frameNumber >= actionFrame && m.frameNumber < expiryFrame {
					actions["Confirm"] = true
				}
			}
			return actions
		case 4:
			// Same window logic using leaveFrame.
			actions := map[string]bool{"Reject": true}
			if row.leaveFrame > 0 {
				actionFrame := row.leaveFrame + ACTION_FRAME_DELAY
				expiryFrame := row.leaveFrame + ACTION_FRAME_DELAY*2
				if m.frameNumber >= actionFrame && m.frameNumber < expiryFrame {
					actions["Confirm"] = true
				}
			}
			return actions
		case 2:
			return map[string]bool{"Leave": true, "Pause": true}
		case 3:
			return map[string]bool{"Leave": true, "Resume": true}
		default:
			return map[string]bool{}
		}
	}

	result := actionsForRow(rows[0])
	for _, row := range rows[1:] {
		rowActions := actionsForRow(row)
		for action := range result {
			if !rowActions[action] {
				delete(result, action)
			}
		}
	}
	return result
}

// applicableActionsLabel returns a human-readable comma-separated list of
// applicable actions for the current focus and selection.
func (m manageModel) applicableActionsLabel() string {
	if m.focus == availablePanel {
		if len(m.freeWorkers) > 0 {
			return "Join"
		}
		return "none (no free workers)"
	}
	actions := m.applicableAllocActions()
	if len(actions) == 0 {
		return "none"
	}
	var names []string
	for _, a := range []string{"Confirm", "Reject", "Leave", "Pause", "Resume"} {
		if actions[a] {
			names = append(names, a)
		}
	}
	return strings.Join(names, ", ")
}

// renderHelpLine renders the key-binding help line with applicable action keys
// highlighted in the primary color and inapplicable ones dimmed.
func (m manageModel) renderHelpScreen() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(mTextColor).Background(mPrimaryColor).Padding(0, 1)
	sectionStyle := lipgloss.NewStyle().Bold(true).Foreground(mPrimaryColor)
	keyStyle := lipgloss.NewStyle().Foreground(mTextColor).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(mHelpColor)
	noteStyle := lipgloss.NewStyle().Foreground(mFilterColor)

	kv := func(k, v string) string {
		return keyStyle.Render(fmt.Sprintf("%-14s", k)) + dimStyle.Render(v)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Width(m.width).Render(" Shard Manager — Help") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Navigation") + "\n")
	b.WriteString("  " + kv("↑ / k", "Move cursor up") + "\n")
	b.WriteString("  " + kv("↓ / j", "Move cursor down") + "\n")
	b.WriteString("  " + kv("Tab", "Switch between Allocations and Available Shards panels") + "\n")
	b.WriteString("  " + kv("Space", "Toggle selection on cursor row (advances cursor)") + "\n")
	b.WriteString("  " + kv("a", "Select all / deselect all rows in current panel") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Actions — Allocations panel") + "\n")
	b.WriteString("  " + kv("l", "Leave  — request to leave an Active allocation (status 2)") + "\n")
	b.WriteString("  " + kv("c", "Confirm — confirm a pending Join/Leave once the window opens") + "\n")
	b.WriteString("  " + kv("r", "Reject  — reject a pending Join/Leave") + "\n")
	b.WriteString("  " + kv("p", "Pause   — pause an Active allocation (status 2)") + "\n")
	b.WriteString("  " + kv("u", "Resume  — resume a Paused allocation (status 3)") + "\n")
	b.WriteString("  " + kv("M", "Toggle manual / auto worker management on cursor row") + "\n")
	b.WriteString("  " + noteStyle.Render("  Multi-select with Space or 'a' to batch Leave/Confirm/Reject/Pause/Resume.") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Actions — Available Shards panel") + "\n")
	b.WriteString("  " + kv("J", "Join    — open worker picker for selected shard(s)") + "\n")
	b.WriteString("  " + noteStyle.Render("  At least one free (unassigned) worker must exist to join.") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Sort mode  (press s)") + "\n")
	b.WriteString("  " + kv("← / →", "Move highlight to previous / next column") + "\n")
	b.WriteString("  " + kv("Enter", "Confirm column, then choose sort order") + "\n")
	b.WriteString("  " + kv("a", "Ascending order") + "\n")
	b.WriteString("  " + kv("d", "Descending order") + "\n")
	b.WriteString("  " + kv("Esc", "Cancel sort mode") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Filter mode  (press f)") + "\n")
	b.WriteString("  " + kv("← / →", "Move highlight to previous / next filterable column") + "\n")
	b.WriteString("  " + kv("Enter", "Open filter editor for highlighted column") + "\n")
	b.WriteString("  " + kv("Del", "Clear filter on highlighted column") + "\n")
	b.WriteString("  " + kv("x", "Disable all filters in current panel") + "\n")
	b.WriteString("  " + kv("Esc", "Close filter mode") + "\n")
	b.WriteString("  " + noteStyle.Render("  Filter editor: text columns accept a substring; numeric columns accept") + "\n")
	b.WriteString("  " + noteStyle.Render("  an expression like \"> 47\", \"< 100\", or a comma list \"1,5,7\";") + "\n")
	b.WriteString("  " + noteStyle.Render("  select columns toggle values with Space, confirm with Enter.") + "\n")
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("General") + "\n")
	b.WriteString("  " + kv("R", "Force data refresh") + "\n")
	b.WriteString("  " + kv("C", "Toggle color-coding of Ring, Status and Mode columns") + "\n")
	b.WriteString("  " + kv("h", "Toggle this help screen") + "\n")
	b.WriteString("  " + kv("q / Ctrl+C", "Quit") + "\n")

	footer := dimStyle.Render("Press h to return")
	b.WriteString("\n" + mFooterStyle.Width(m.width).Render(footer))

	return b.String()
}

func (m manageModel) renderHelpLine() string {
	applicable := map[string]bool{}
	if !m.actionInFlight {
		if m.focus == allocationsPanel {
			for a := range m.applicableAllocActions() {
				applicable[a] = true
			}
			sorted := m.sortedAllocations()
			if m.allocCursor < len(sorted) && sorted[m.allocCursor].workerID >= 0 {
				applicable["ToggleManual"] = true
			}
		} else {
			if len(m.freeWorkers) > 0 {
				applicable["Join"] = true
			}
		}
	}

	type helpEntry struct {
		b      key.Binding
		action string // empty = always shown in normal help color; "Filter" = filter indicator
	}
	entries := []helpEntry{
		{m.keyMap.Tab, ""},
		{m.keyMap.Up, ""},
		{m.keyMap.Down, ""},
		{m.keyMap.Select, ""},
		{m.keyMap.SelectAll, ""},
		{m.keyMap.Join, "Join"},
		{m.keyMap.Leave, "Leave"},
		{m.keyMap.Confirm, "Confirm"},
		{m.keyMap.Reject, "Reject"},
		{m.keyMap.Pause, "Pause"},
		{m.keyMap.Resume, "Resume"},
		{m.keyMap.ToggleManual, "ToggleManual"},
		{m.keyMap.Refresh, ""},
		{m.keyMap.Sort, ""},
		{m.keyMap.Filter, "Filter"},
		{m.keyMap.ColorCoding, "ColorCoding"},
		{m.keyMap.Help, ""},
		{m.keyMap.Quit, ""},
	}

	filtersActive := m.hasActiveFilters()

	var parts []string
	for _, e := range entries {
		h := e.b.Help()
		text := h.Key + " " + h.Desc
		switch {
		case e.action == "Filter":
			// Use a distinct amber color when filtering is enabled.
			if filtersActive {
				parts = append(parts, lipgloss.NewStyle().Foreground(mFilterColor).Bold(true).Render(text))
			} else {
				parts = append(parts, lipgloss.NewStyle().Foreground(mHelpColor).Render(text))
			}
		case e.action == "ColorCoding":
			// Highlight in green when color-coding is on, match normal help color when off.
			if m.colorCoding {
				parts = append(parts, lipgloss.NewStyle().Foreground(mStatusActiveColor).Render(text))
			} else {
				parts = append(parts, lipgloss.NewStyle().Foreground(mHelpColor).Render(text))
			}
		case e.action == "":
			parts = append(parts, lipgloss.NewStyle().Foreground(mHelpColor).Render(text))
		case applicable[e.action]:
			parts = append(parts, lipgloss.NewStyle().Foreground(mPrimaryColor).Bold(true).Render(text))
		default:
			parts = append(parts, lipgloss.NewStyle().Foreground(mDimColor).Render(text))
		}
	}
	return strings.Join(parts, "  ")
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

// ── Filter helpers ──────────────────────────────────────────────────────────

// activePanelFilterCols returns the filterable column indices for the focused panel.
func (m manageModel) activePanelFilterCols() []int {
	if m.focus == allocationsPanel {
		return allocFilterableCols
	}
	return availFilterableCols
}

// isFilterModeActive returns true when the focused panel is in filter navigation mode.
func (m manageModel) isFilterModeActive() bool {
	if m.focus == allocationsPanel {
		return m.allocFilterMode
	}
	return m.availFilterMode
}

// getFilterHighlightIdx returns the filter highlight index for the focused panel.
func (m manageModel) getFilterHighlightIdx() int {
	if m.focus == allocationsPanel {
		return m.allocFilterHighlightIdx
	}
	return m.availFilterHighlightIdx
}

// activeFilterColIdx returns the absolute column index currently highlighted in filter mode.
func (m manageModel) activeFilterColIdx() int {
	cols := m.activePanelFilterCols()
	idx := m.getFilterHighlightIdx()
	if idx < len(cols) {
		return cols[idx]
	}
	return -1
}

// activeFilterColKind returns the filter kind for a column in the focused panel.
func (m manageModel) activeFilterColKind(colIdx int) filterColKind {
	if m.focus == allocationsPanel {
		return allocFilterColKinds[colIdx]
	}
	return availFilterColKinds[colIdx]
}

// activeFilterCol returns the current columnFilter for a column in the focused panel.
func (m manageModel) activeFilterCol(colIdx int) columnFilter {
	if m.focus == allocationsPanel {
		return m.allocColFilters[colIdx]
	}
	return m.availColFilters[colIdx]
}

// setActiveFilterCol stores a columnFilter for a column in the focused panel.
func (m *manageModel) setActiveFilterCol(colIdx int, cf columnFilter) {
	if m.focus == allocationsPanel {
		if cf.isActive() {
			m.allocColFilters[colIdx] = cf
		} else {
			delete(m.allocColFilters, colIdx)
		}
	} else {
		if cf.isActive() {
			m.availColFilters[colIdx] = cf
		} else {
			delete(m.availColFilters, colIdx)
		}
	}
}

// hasActiveFilters returns true if any column filter is active in the focused panel.
func (m manageModel) hasActiveFilters() bool {
	if m.focus == allocationsPanel {
		for _, cf := range m.allocColFilters {
			if cf.isActive() {
				return true
			}
		}
		return false
	}
	for _, cf := range m.availColFilters {
		if cf.isActive() {
			return true
		}
	}
	return false
}

// filterSelectValues returns the set of unique values for a select-kind column.
func (m manageModel) filterSelectValues(colIdx int) []string {
	seen := make(map[string]bool)
	if m.focus == allocationsPanel {
		for _, row := range m.allocations {
			v := allocRowTextVal(row, colIdx)
			if v != "" {
				seen[v] = true
			}
		}
	}
	var vals []string
	for v := range seen {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	return vals
}

// clampCursors clamps panel cursors to valid ranges after filter changes.
func (m *manageModel) clampCursors() {
	if sorted := m.sortedAllocations(); m.allocCursor >= len(sorted) {
		m.allocCursor = max(0, len(sorted)-1)
	}
	if sorted := m.sortedAvailable(); m.availCursor >= len(sorted) {
		m.availCursor = max(0, len(sorted)-1)
	}
}

// allocRowNumericVal returns the numeric value for a filterable numeric column.
func allocRowNumericVal(row allocationRow, colIdx int) float64 {
	switch colIdx {
	case 2:
		return float64(row.activeProvers)
	case 3:
		return float64(row.ring)
	case 4:
		if row.shardSize == nil {
			return 0
		}
		return float64(row.shardSize.Uint64()) / float64(1024*1024)
	case 5:
		return float64(row.dataShards)
	case 6:
		if row.estimatedReward == nil || row.estimatedReward.Sign() == 0 {
			return 0
		}
		f, _ := new(big.Float).SetInt(row.estimatedReward).Float64()
		return f / 1e8
	case 7:
		return float64(row.workerID)
	}
	return 0
}

// allocRowTextVal returns the text value for a filterable text/select column.
func allocRowTextVal(row allocationRow, colIdx int) string {
	switch colIdx {
	case 1:
		return row.filterHex
	case 8:
		return row.statusName
	case 9:
		if row.manuallyManaged {
			return "M"
		}
		return "A"
	}
	return ""
}

// availRowNumericVal returns the numeric value for a filterable numeric column (available panel).
func availRowNumericVal(row shardRow, colIdx int) float64 {
	switch colIdx {
	case 2:
		return float64(row.activeProvers)
	case 3:
		return float64(row.ring)
	case 4:
		if row.shardSize == nil {
			return 0
		}
		return float64(row.shardSize.Uint64()) / float64(1024*1024)
	case 5:
		return float64(row.dataShards)
	case 6:
		if row.estimatedReward == nil || row.estimatedReward.Sign() == 0 {
			return 0
		}
		f, _ := new(big.Float).SetInt(row.estimatedReward).Float64()
		return f / 1e8
	}
	return 0
}

// parseNumericExpr parses a filter expression such as "> 47", ">= 5.5", "=3", or "1,3,7".
// Returns (op, threshold, values); op is "", ">", ">=", "<", "<=", "=" or "in".
func parseNumericExpr(expr string) (op string, threshold float64, values []float64) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", 0, nil
	}
	for _, prefix := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(expr, prefix) {
			rest := strings.TrimSpace(expr[len(prefix):])
			v, err := strconv.ParseFloat(rest, 64)
			if err != nil {
				return "", 0, nil
			}
			return prefix, v, nil
		}
	}
	// Comma-separated value list.
	parts := strings.Split(expr, ",")
	var vals []float64
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return "", 0, nil
		}
		vals = append(vals, v)
	}
	if len(vals) > 0 {
		return "in", 0, vals
	}
	return "", 0, nil
}

// matchesNumericExpr returns true if val satisfies the filter expression.
func matchesNumericExpr(val float64, expr string) bool {
	if expr == "" {
		return true
	}
	op, threshold, values := parseNumericExpr(expr)
	switch op {
	case ">":
		return val > threshold
	case ">=":
		return val >= threshold
	case "<":
		return val < threshold
	case "<=":
		return val <= threshold
	case "=":
		return val == threshold
	case "in":
		parts := strings.Split(expr, ",")
		for i, v := range values {
			if val == v {
				return true
			}
			// For filter values with a decimal point, compare using formatted strings
			// to handle float64 precision (e.g. "47.1" should match 47.09375 displayed as "47.1").
			if i < len(parts) {
				part := strings.TrimSpace(parts[i])
				if dotIdx := strings.IndexByte(part, '.'); dotIdx >= 0 {
					decimals := len(part) - dotIdx - 1
					if fmt.Sprintf("%.*f", decimals, val) == part {
						return true
					}
				}
			}
		}
		return false
	}
	return true // unparseable = no filter
}

// ── Key handlers ─────────────────────────────────────────────────────────────

func (m manageModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.joinPickerActive {
		return m.handleJoinPickerKey(msg)
	}
	if m.filterEditActive {
		return m.handleFilterEditKey(msg)
	}
	if m.isFilterModeActive() {
		return m.handleFilterModeKey(msg)
	}
	if m.sortMode && m.sortOrderMode {
		return m.handleSortOrderKey(msg)
	}
	if m.sortMode {
		return m.handleSortModeKey(msg)
	}

	switch {
	case key.Matches(msg, m.keyMap.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keyMap.Help):
		m.showHelp = !m.showHelp
		return m, nil

	case key.Matches(msg, m.keyMap.ColorCoding):
		m.colorCoding = !m.colorCoding
		return m, nil

	case key.Matches(msg, m.keyMap.Tab):
		if m.focus == allocationsPanel {
			m.focus = availablePanel
		} else {
			m.focus = allocationsPanel
		}
		m.filterEditActive = false

	case key.Matches(msg, m.keyMap.Select):
		if m.focus == allocationsPanel {
			sorted := m.sortedAllocations()
			if m.allocCursor < len(sorted) {
				k := sorted[m.allocCursor].filterKey
				if m.allocSelected[k] {
					delete(m.allocSelected, k)
				} else {
					m.allocSelected[k] = true
				}
				// Advance cursor after toggle.
				if m.allocCursor < len(sorted)-1 {
					m.allocCursor++
				}
			}
		} else {
			sorted := m.sortedAvailable()
			if m.availCursor < len(sorted) {
				k := sorted[m.availCursor].filterKey
				if m.availSelected[k] {
					delete(m.availSelected, k)
				} else {
					m.availSelected[k] = true
				}
				if m.availCursor < len(sorted)-1 {
					m.availCursor++
				}
			}
		}

	case key.Matches(msg, m.keyMap.SelectAll):
		if m.focus == allocationsPanel {
			sorted := m.sortedAllocations()
			allSelected := len(m.allocSelected) == len(sorted) && len(sorted) > 0
			m.allocSelected = make(map[string]bool)
			if !allSelected {
				for _, row := range sorted {
					m.allocSelected[row.filterKey] = true
				}
			}
		} else {
			sorted := m.sortedAvailable()
			allSelected := len(m.availSelected) == len(sorted) && len(sorted) > 0
			m.availSelected = make(map[string]bool)
			if !allSelected {
				for _, row := range sorted {
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
			sorted := m.sortedAllocations()
			if m.allocCursor < len(sorted)-1 {
				m.allocCursor++
			}
		} else {
			sorted := m.sortedAvailable()
			if m.availCursor < len(sorted)-1 {
				m.availCursor++
			}
		}

	case key.Matches(msg, m.keyMap.Refresh):
		return m, fetchData(m.client)

	case key.Matches(msg, m.keyMap.Join):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != availablePanel {
			m.statusMsg = "Join is only available in the Available Shards panel (Tab to switch)"
			m.statusIsError = true
			return m, nil
		}
		if len(m.freeWorkers) == 0 {
			m.statusMsg = "Join requires at least one free worker"
			m.statusIsError = true
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
		m.joinPickerActive = true
		m.joinPickerCursor = 0
		m.joinPickerWorkers = append([]uint32(nil), m.freeWorkers...)
		m.joinPickerSelected = make(map[uint32]bool)
		m.joinPickerFilters = filters
		return m, nil

	case key.Matches(msg, m.keyMap.Leave):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Leave is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		return m.startMultiFilterAction("Leave", m.selectedAllocRows(), func(s uint32) bool { return s == 2 })

	case key.Matches(msg, m.keyMap.Confirm):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Confirm is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		// Pre-filter to rows whose confirmation window is currently open.
		var confirmRows []allocationRow
		var earliestConfirmFrame uint64
		for _, row := range m.selectedAllocRows() {
			var actionFrame uint64
			switch row.status {
			case 1:
				if row.joinFrame > 0 {
					actionFrame = row.joinFrame + ACTION_FRAME_DELAY
					if m.frameNumber >= actionFrame && m.frameNumber < row.joinFrame+ACTION_FRAME_DELAY*2 {
						confirmRows = append(confirmRows, row)
					}
				}
			case 4:
				if row.leaveFrame > 0 {
					actionFrame = row.leaveFrame + ACTION_FRAME_DELAY
					if m.frameNumber >= actionFrame && m.frameNumber < row.leaveFrame+ACTION_FRAME_DELAY*2 {
						confirmRows = append(confirmRows, row)
					}
				}
			}
			if actionFrame > m.frameNumber && (earliestConfirmFrame == 0 || actionFrame < earliestConfirmFrame) {
				earliestConfirmFrame = actionFrame
			}
		}
		if len(confirmRows) == 0 && earliestConfirmFrame > 0 {
			m.statusMsg = fmt.Sprintf("Confirm not yet available (current frame: %d, opens at: %d). Applicable action(s): Reject", m.frameNumber, earliestConfirmFrame)
			m.statusIsError = true
			return m, nil
		}
		return m.startMultiFilterAction("Confirm", confirmRows, func(s uint32) bool { return s == 1 || s == 4 })

	case key.Matches(msg, m.keyMap.Reject):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Reject is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		return m.startMultiFilterAction("Reject", m.selectedAllocRows(), func(s uint32) bool { return s == 1 || s == 4 })

	case key.Matches(msg, m.keyMap.Pause):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Pause is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		return m.startBatchAction("Pause", m.selectedAllocRows(), func(s uint32) bool { return s == 2 })

	case key.Matches(msg, m.keyMap.Resume):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Resume is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		return m.startBatchAction("Resume", m.selectedAllocRows(), func(s uint32) bool { return s == 3 })

	case key.Matches(msg, m.keyMap.ToggleManual):
		if m.actionInFlight {
			return m, nil
		}
		if m.focus != allocationsPanel {
			m.statusMsg = fmt.Sprintf("Mode toggle is only available in the Allocations panel (Tab to switch). Current panel supports: %s", m.applicableActionsLabel())
			m.statusIsError = true
			return m, nil
		}
		sorted := m.sortedAllocations()
		if m.allocCursor >= len(sorted) {
			return m, nil
		}
		row := sorted[m.allocCursor]
		if row.workerID < 0 {
			m.statusMsg = "No worker assigned to this allocation"
			m.statusIsError = true
			return m, nil
		}
		newState := !row.manuallyManaged
		return m, doToggleManual(m.client, uint32(row.workerID), newState)

	case key.Matches(msg, m.keyMap.Sort):
		m.sortMode = true
		m.sortOrderMode = false
		m.sortHighlightCol = 0

	case key.Matches(msg, m.keyMap.Filter):
		if m.focus == allocationsPanel {
			m.allocFilterMode = true
			m.allocFilterHighlightIdx = 0
		} else {
			m.availFilterMode = true
			m.availFilterHighlightIdx = 0
		}
		m.filterEditActive = false
	}

	return m, nil
}

// processRefreshData merges NodeInfo + ShardInfo into model state.
func (m *manageModel) processRefreshData(
	nodeInfo *protobufs.NodeInfoResponse,
	shardInfo *protobufs.GetShardInfoResponse,
	workerInfo *protobufs.WorkerInfoResponse,
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

	// Build maps of worker core_id and manually-managed state by filter hex.
	type workerData struct {
		coreId          uint32
		manuallyManaged bool
	}
	workers := make(map[string]workerData)
	anyManuallyManaged := false
	if workerInfo != nil {
		for _, w := range workerInfo.GetWorkerInfo() {
			workers[hex.EncodeToString(w.GetFilter())] = workerData{
				coreId:          w.GetCoreId(),
				manuallyManaged: w.GetManuallyManaged(),
			}
			if w.GetManuallyManaged() {
				anyManuallyManaged = true
			}
		}
	}
	m.autoManaged = !anyManuallyManaged

	// Collect free workers (no filter assigned).
	var freeWorkers []uint32
	if workerInfo != nil {
		for _, w := range workerInfo.GetWorkerInfo() {
			if len(w.GetFilter()) == 0 {
				freeWorkers = append(freeWorkers, w.GetCoreId())
			}
		}
	}
	sort.Slice(freeWorkers, func(i, j int) bool { return freeWorkers[i] < freeWorkers[j] })
	m.freeWorkers = freeWorkers

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
		// Only show allocations the prover is actively participating in.
		s := a.GetStatus()
		if s != 1 && s != 2 && s != 3 && s != 4 {
			continue
		}
		// Skip expired joins (implicitly rejected after 720 frames).
		if s == 1 && a.GetJoinFrameNumber() > 0 &&
			m.frameNumber >= a.GetJoinFrameNumber()+ACTION_FRAME_DELAY*2 {
			continue
		}
		// Skip expired leaves (implicitly left after 720 frames).
		if s == 4 && a.GetLeaveFrameNumber() > 0 &&
			m.frameNumber >= a.GetLeaveFrameNumber()+ACTION_FRAME_DELAY*2 {
			continue
		}
		filterHex := hex.EncodeToString(a.GetFilter())
		allocatedFilters[filterHex] = true

		statusName, ok := allocationStatusNames[a.GetStatus()]
		if !ok {
			statusName = fmt.Sprintf("Unknown(%d)", a.GetStatus())
		}

		nextAction := ""
		defaultAction := ""
		// For Joining, annotate with confirmable frame.
		if a.GetStatus() == 1 && a.GetJoinFrameNumber() > 0 {
			actionFrame := a.GetJoinFrameNumber() + ACTION_FRAME_DELAY
			expiryFrame := a.GetJoinFrameNumber() + ACTION_FRAME_DELAY*2
			if m.frameNumber >= actionFrame && m.frameNumber < expiryFrame {
				nextAction = "Reject@now | Confirm@now"
			} else {
				nextAction = fmt.Sprintf("Reject@now | Confirm@%d", actionFrame)
			}
			defaultAction = fmt.Sprintf("Reject@%d", expiryFrame)
		} else if a.GetStatus() == 4 && a.GetLeaveFrameNumber() > 0 {
			// For Leaving, use LeaveFrameNumber for action/expiry calculation.
			actionFrame := a.GetLeaveFrameNumber() + ACTION_FRAME_DELAY
			expiryFrame := a.GetLeaveFrameNumber() + ACTION_FRAME_DELAY*2
			if m.frameNumber >= actionFrame && m.frameNumber < expiryFrame {
				nextAction = "Reject@now | Confirm@now"
			} else {
				nextAction = fmt.Sprintf("Reject@now | Confirm@%d", actionFrame)
			}
			defaultAction = fmt.Sprintf("Confirm@%d", expiryFrame)
		} else if a.GetStatus() == 2 {
			nextAction = "Pause@now | Leave@now"
		} else if a.GetStatus() == 3 {
			nextAction = "Resume@now | Leave@now"
		}

		wid := -1
		mm := false
		if wd, ok := workers[filterHex]; ok {
			wid = int(wd.coreId)
			mm = wd.manuallyManaged
		}

		row := allocationRow{
			filter:          a.GetFilter(),
			filterKey:       filterHex,
			filterHex:       filterHex,
			status:          a.GetStatus(),
			statusName:      statusName,
			joinFrame:       a.GetJoinFrameNumber(),
			confirmFrame:    a.GetJoinConfirmFrameNumber(),
			leaveFrame:      a.GetLeaveFrameNumber(),
			lastActiveFrame: a.GetLastActiveFrameNumber(),
			shardSize:       big.NewInt(0),
			estimatedReward: big.NewInt(0),
			workerID:        wid,
			nextAction:      nextAction,
			defaultAction:   defaultAction,
			manuallyManaged: mm,
		}

		if info, ok := rewardByFilter[filterHex]; ok {
			row.ring = info.GetRing()
			row.activeProvers = info.GetActiveProvers()
			row.shardSize = new(big.Int).SetBytes(info.GetShardSize())
			row.dataShards = info.GetDataShards()
			row.estimatedReward = new(big.Int).SetBytes(info.GetEstimatedReward())
		}

		allocs = append(allocs, row)
	}

	// Add rows for workers with empty filters (idle workers not assigned to any shard).
	if workerInfo != nil {
		for _, w := range workerInfo.GetWorkerInfo() {
			if len(w.GetFilter()) == 0 {
				allocs = append(allocs, allocationRow{
					filterKey:       fmt.Sprintf("worker:%d", w.GetCoreId()),
					filterHex:       "",
					status:          0,
					statusName:      "Idle",
					shardSize:       big.NewInt(0),
					estimatedReward: big.NewInt(0),
					workerID:        int(w.GetCoreId()),
					manuallyManaged: w.GetManuallyManaged(),
				})
			}
		}
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
				filterHex:       filterHex,
				activeProvers:   s.GetActiveProvers(),
				ring:            s.GetRing(),
				shardSize:       new(big.Int).SetBytes(s.GetShardSize()),
				dataShards:      s.GetDataShards(),
				estimatedReward: new(big.Int).SetBytes(s.GetEstimatedReward()),
			})
		}
	}

	m.available = avail

	// Clamp cursors.
	if sorted := m.sortedAllocations(); m.allocCursor >= len(sorted) {
		m.allocCursor = max(0, len(sorted)-1)
	}
	if sorted := m.sortedAvailable(); m.availCursor >= len(sorted) {
		m.availCursor = max(0, len(sorted)-1)
	}
}

func (m manageModel) filteredAllocations() []allocationRow {
	if len(m.allocColFilters) == 0 {
		return m.allocations
	}
	var out []allocationRow
	for _, row := range m.allocations {
		if m.allocRowMatchesFilters(row) {
			out = append(out, row)
		}
	}
	return out
}

func (m manageModel) allocRowMatchesFilters(row allocationRow) bool {
	for colIdx, cf := range m.allocColFilters {
		if !cf.isActive() {
			continue
		}
		switch allocFilterColKinds[colIdx] {
		case filterColText:
			if !strings.Contains(row.filterHex, cf.text) {
				return false
			}
		case filterColNumeric:
			if !matchesNumericExpr(allocRowNumericVal(row, colIdx), cf.expr) {
				return false
			}
		case filterColSelect:
			if len(cf.values) > 0 && !cf.values[allocRowTextVal(row, colIdx)] {
				return false
			}
		}
	}
	return true
}

func (m manageModel) filteredAvailable() []shardRow {
	if len(m.availColFilters) == 0 {
		return m.available
	}
	var out []shardRow
	for _, row := range m.available {
		if m.availRowMatchesFilters(row) {
			out = append(out, row)
		}
	}
	return out
}

func (m manageModel) availRowMatchesFilters(row shardRow) bool {
	for colIdx, cf := range m.availColFilters {
		if !cf.isActive() {
			continue
		}
		switch availFilterColKinds[colIdx] {
		case filterColText:
			if !strings.Contains(row.filterHex, cf.text) {
				return false
			}
		case filterColNumeric:
			if !matchesNumericExpr(availRowNumericVal(row, colIdx), cf.expr) {
				return false
			}
		}
	}
	return true
}

// sortedAllocations returns filtered allocations sorted by the active sort column.
func (m manageModel) sortedAllocations() []allocationRow {
	rows := m.filteredAllocations()
	if m.allocSortCol < 0 {
		return rows
	}
	sorted := make([]allocationRow, len(rows))
	copy(sorted, rows)
	col := m.allocSortCol
	asc := m.allocSortAsc
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		switch col {
		case 0: // Select – selected items first
			ai := m.allocSelected[a.filterKey]
			bi := m.allocSelected[b.filterKey]
			if asc {
				return !ai && bi
			}
			return ai && !bi
		case 1: // Filter
			if asc {
				return a.filterHex < b.filterHex
			}
			return a.filterHex > b.filterHex
		case 2: // Provers
			if asc {
				return a.activeProvers < b.activeProvers
			}
			return a.activeProvers > b.activeProvers
		case 3: // Ring
			if asc {
				return a.ring < b.ring
			}
			return a.ring > b.ring
		case 4: // Size
			c := a.shardSize.Cmp(b.shardSize)
			if asc {
				return c < 0
			}
			return c > 0
		case 5: // Shards
			if asc {
				return a.dataShards < b.dataShards
			}
			return a.dataShards > b.dataShards
		case 6: // Reward
			c := a.estimatedReward.Cmp(b.estimatedReward)
			if asc {
				return c < 0
			}
			return c > 0
		case 7: // Worker
			if asc {
				return a.workerID < b.workerID
			}
			return a.workerID > b.workerID
		case 8: // Status
			if asc {
				return a.status < b.status
			}
			return a.status > b.status
		case 9: // Mode
			if asc {
				return !a.manuallyManaged && b.manuallyManaged
			}
			return a.manuallyManaged && !b.manuallyManaged
		case 10: // Next Action
			if asc {
				return a.nextAction < b.nextAction
			}
			return a.nextAction > b.nextAction
		case 11: // Default Action
			if asc {
				return a.defaultAction < b.defaultAction
			}
			return a.defaultAction > b.defaultAction
		}
		return false
	})
	return sorted
}

// sortedAvailable returns filtered available shards sorted by the active sort column.
func (m manageModel) sortedAvailable() []shardRow {
	rows := m.filteredAvailable()
	if m.availSortCol < 0 {
		return rows
	}
	sorted := make([]shardRow, len(rows))
	copy(sorted, rows)
	col := m.availSortCol
	asc := m.availSortAsc
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		switch col {
		case 0: // Select – selected items first
			ai := m.availSelected[a.filterKey]
			bi := m.availSelected[b.filterKey]
			if asc {
				return !ai && bi
			}
			return ai && !bi
		case 1: // Filter
			if asc {
				return a.filterHex < b.filterHex
			}
			return a.filterHex > b.filterHex
		case 2: // Provers
			if asc {
				return a.activeProvers < b.activeProvers
			}
			return a.activeProvers > b.activeProvers
		case 3: // Ring
			if asc {
				return a.ring < b.ring
			}
			return a.ring > b.ring
		case 4: // Size
			c := a.shardSize.Cmp(b.shardSize)
			if asc {
				return c < 0
			}
			return c > 0
		case 5: // Shards
			if asc {
				return a.dataShards < b.dataShards
			}
			return a.dataShards > b.dataShards
		case 6: // Reward
			c := a.estimatedReward.Cmp(b.estimatedReward)
			if asc {
				return c < 0
			}
			return c > 0
		}
		return false
	})
	return sorted
}

// activePanelColCount returns the number of sortable columns in the focused panel.
func (m manageModel) activePanelColCount() int {
	if m.focus == allocationsPanel {
		return 11 // Select, Filter, Provers, Ring, Size, Shards, Reward, Worker, Status, Next Action, Default Action
	}
	return 7 // Select, Filter, Provers, Ring, Size, Shards, Reward
}

// handleSortModeKey processes key events while column selection is active.
func (m manageModel) handleSortModeKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	rightKey := key.NewBinding(key.WithKeys("right"))
	leftKey := key.NewBinding(key.WithKeys("left"))
	enterKey := key.NewBinding(key.WithKeys("enter"))
	escKey := key.NewBinding(key.WithKeys("esc"))

	numCols := m.activePanelColCount()

	switch {
	case key.Matches(msg, rightKey):
		m.sortHighlightCol = (m.sortHighlightCol + 1) % numCols
	case key.Matches(msg, leftKey):
		m.sortHighlightCol = (m.sortHighlightCol - 1 + numCols) % numCols
	case key.Matches(msg, enterKey):
		m.sortOrderMode = true
	case key.Matches(msg, escKey), key.Matches(msg, m.keyMap.Quit):
		m.sortMode = false
		m.sortOrderMode = false
		m.sortHighlightCol = 0
	}
	return m, nil
}

// handleSortOrderKey processes key events while the sort order prompt is active.
func (m manageModel) handleSortOrderKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	enterKey := key.NewBinding(key.WithKeys("enter"))
	aKey := key.NewBinding(key.WithKeys("a", "A"))
	dKey := key.NewBinding(key.WithKeys("d", "D"))
	escKey := key.NewBinding(key.WithKeys("esc"))

	switch {
	case key.Matches(msg, enterKey), key.Matches(msg, aKey):
		m.applySort(true)
		m.sortMode = false
		m.sortOrderMode = false
	case key.Matches(msg, dKey):
		m.applySort(false)
		m.sortMode = false
		m.sortOrderMode = false
	case key.Matches(msg, escKey), key.Matches(msg, m.keyMap.Quit):
		m.sortMode = false
		m.sortOrderMode = false
		m.sortHighlightCol = 0
	}
	return m, nil
}

// handleFilterModeKey processes key events during filter column navigation.
func (m manageModel) handleFilterModeKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	rightKey := key.NewBinding(key.WithKeys("right"))
	leftKey := key.NewBinding(key.WithKeys("left"))
	enterKey := key.NewBinding(key.WithKeys("enter"))
	escKey := key.NewBinding(key.WithKeys("esc"))
	delKey := key.NewBinding(key.WithKeys("delete", "backspace"))
	xKey := key.NewBinding(key.WithKeys("x"))

	filterCols := m.activePanelFilterCols()
	numCols := len(filterCols)
	hiIdx := m.getFilterHighlightIdx()

	setHiIdx := func(idx int) {
		if m.focus == allocationsPanel {
			m.allocFilterHighlightIdx = idx
		} else {
			m.availFilterHighlightIdx = idx
		}
	}
	closeFilterMode := func() {
		if m.focus == allocationsPanel {
			m.allocFilterMode = false
		} else {
			m.availFilterMode = false
		}
	}

	switch {
	case key.Matches(msg, rightKey):
		setHiIdx((hiIdx + 1) % numCols)
	case key.Matches(msg, leftKey):
		setHiIdx((hiIdx - 1 + numCols) % numCols)
	case key.Matches(msg, enterKey):
		if hiIdx < numCols {
			colIdx := filterCols[hiIdx]
			kind := m.activeFilterColKind(colIdx)
			m.filterEditColIdx = colIdx
			m.filterEditActive = true
			switch kind {
			case filterColText:
				m.filterEditInput = m.activeFilterCol(colIdx).text
			case filterColNumeric:
				m.filterEditInput = m.activeFilterCol(colIdx).expr
			case filterColSelect:
				m.filterEditSelectItems = m.filterSelectValues(colIdx)
				existing := m.activeFilterCol(colIdx)
				m.filterEditSelectState = make(map[string]bool)
				if len(existing.values) > 0 {
					for v := range existing.values {
						m.filterEditSelectState[v] = true
					}
				} else {
					// No active filter = all items "selected" (shown)
					for _, v := range m.filterEditSelectItems {
						m.filterEditSelectState[v] = true
					}
				}
				m.filterEditSelectCursor = 0
			}
		}
	case key.Matches(msg, delKey):
		// Clear filter for the highlighted column.
		if hiIdx < numCols {
			colIdx := filterCols[hiIdx]
			m.setActiveFilterCol(colIdx, columnFilter{})
			m.clampCursors()
		}
	case key.Matches(msg, xKey):
		// Disable all filtering for the focused panel only.
		closeFilterMode()
		m.filterEditActive = false
		if m.focus == allocationsPanel {
			m.allocColFilters = make(map[int]columnFilter)
		} else {
			m.availColFilters = make(map[int]columnFilter)
		}
		m.clampCursors()
	case key.Matches(msg, escKey):
		// Close filter panel without clearing filters.
		closeFilterMode()
		m.filterEditActive = false
	case key.Matches(msg, m.keyMap.Quit):
		return m, tea.Quit
	}
	return m, nil
}

// handleFilterEditKey dispatches to the appropriate edit handler.
func (m manageModel) handleFilterEditKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	kind := m.activeFilterColKind(m.filterEditColIdx)
	if kind == filterColSelect {
		return m.handleFilterSelectKey(msg)
	}
	return m.handleFilterTextKey(msg)
}

// handleFilterTextKey handles text/numeric filter input.
func (m manageModel) handleFilterTextKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	enterKey := key.NewBinding(key.WithKeys("enter"))
	escKey := key.NewBinding(key.WithKeys("esc"))
	bsKey := key.NewBinding(key.WithKeys("backspace", "ctrl+h"))

	switch {
	case key.Matches(msg, enterKey):
		kind := m.activeFilterColKind(m.filterEditColIdx)
		cf := columnFilter{}
		switch kind {
		case filterColText:
			cf.text = m.filterEditInput
		case filterColNumeric:
			cf.expr = m.filterEditInput
		}
		m.setActiveFilterCol(m.filterEditColIdx, cf)
		m.filterEditActive = false
		m.filterEditInput = ""
		m.clampCursors()
	case key.Matches(msg, escKey):
		m.filterEditActive = false
		m.filterEditInput = ""
	case key.Matches(msg, bsKey):
		runes := []rune(m.filterEditInput)
		if len(runes) > 0 {
			m.filterEditInput = string(runes[:len(runes)-1])
		}
	default:
		if msg.Text != "" {
			m.filterEditInput += msg.Text
		}
	}
	return m, nil
}

// handleFilterSelectKey handles multi-value select filter input.
func (m manageModel) handleFilterSelectKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	enterKey := key.NewBinding(key.WithKeys("enter"))
	escKey := key.NewBinding(key.WithKeys("esc"))
	rightKey := key.NewBinding(key.WithKeys("right"))
	leftKey := key.NewBinding(key.WithKeys("left"))
	aKey := key.NewBinding(key.WithKeys("a", "A"))
	n := len(m.filterEditSelectItems)

	switch {
	case key.Matches(msg, rightKey):
		if n > 0 {
			m.filterEditSelectCursor = (m.filterEditSelectCursor + 1) % n
		}
	case key.Matches(msg, leftKey):
		if n > 0 {
			m.filterEditSelectCursor = (m.filterEditSelectCursor - 1 + n) % n
		}
	case key.Matches(msg, m.keyMap.Select): // space
		if m.filterEditSelectCursor < n {
			v := m.filterEditSelectItems[m.filterEditSelectCursor]
			m.filterEditSelectState[v] = !m.filterEditSelectState[v]
		}
	case key.Matches(msg, aKey):
		// Toggle all: if all are selected, deselect all; otherwise select all.
		allSelected := true
		for _, v := range m.filterEditSelectItems {
			if !m.filterEditSelectState[v] {
				allSelected = false
				break
			}
		}
		for _, v := range m.filterEditSelectItems {
			m.filterEditSelectState[v] = !allSelected
		}
	case key.Matches(msg, enterKey):
		// Build value set. If all items are selected (or no items exist), clear the filter.
		values := make(map[string]bool)
		allSelected := true
		for _, v := range m.filterEditSelectItems {
			if m.filterEditSelectState[v] {
				values[v] = true
			} else {
				allSelected = false
			}
		}
		cf := columnFilter{}
		if !allSelected && len(values) > 0 {
			cf.values = values
		}
		m.setActiveFilterCol(m.filterEditColIdx, cf)
		m.filterEditActive = false
		m.filterEditSelectState = nil
		m.clampCursors()
	case key.Matches(msg, escKey):
		m.filterEditActive = false
		m.filterEditSelectState = nil
	}
	return m, nil
}

// applySort applies the selected column and direction to the active panel.
func (m *manageModel) applySort(asc bool) {
	if m.focus == allocationsPanel {
		m.allocSortCol = m.sortHighlightCol
		m.allocSortAsc = asc
	} else {
		m.availSortCol = m.sortHighlightCol
		m.availSortAsc = asc
	}
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

	if m.joinPickerActive {
		return m.renderJoinPicker()
	}

	if m.showHelp {
		return m.renderHelpScreen()
	}

	var doc strings.Builder

	// Header bar.
	peerDisplay := m.peerId
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
	// Reserve: header(1) + alloc title(1) + alloc border(2) + avail title(1) + avail border(2) + help(1) + status(1) = 10
	panelBudget := m.height - 10
	if panelBudget < 4 {
		panelBudget = 4
	}
	allocHeight := panelBudget / 2
	availHeight := panelBudget - allocHeight

	// Allocations panel.
	sortedAllocs := m.sortedAllocations()
	activePerFrame := big.NewInt(0)
	joiningPerFrame := big.NewInt(0)
	pausedPerFrame := big.NewInt(0)
	leavingPerFrame := big.NewInt(0)
	for _, a := range sortedAllocs {
		switch a.status {
		case 1:
			joiningPerFrame.Add(joiningPerFrame, a.estimatedReward)
		case 2:
			activePerFrame.Add(activePerFrame, a.estimatedReward)
		case 3:
			pausedPerFrame.Add(pausedPerFrame, a.estimatedReward)
		case 4:
			leavingPerFrame.Add(leavingPerFrame, a.estimatedReward)
		}

	}
	totalPerFrame := big.NewInt(0)
	totalPerFrame.Add(totalPerFrame, joiningPerFrame)
	totalPerFrame.Add(totalPerFrame, activePerFrame)
	totalPerFrame.Add(totalPerFrame, pausedPerFrame)
	totalPerFrame.Add(totalPerFrame, leavingPerFrame)

	allocTitle := fmt.Sprintf("Allocations (%d) Rewards: Total ~%s QUIL/day = Joining ~%s QUIL/day + Active ~%s QUIL/day + Paused ~%s QUIL/day + Leaving ~%s QUIL/day",
		len(sortedAllocs), formatQUILDaily(totalPerFrame), formatQUILDaily(joiningPerFrame), formatQUILDaily(activePerFrame),
		formatQUILDaily(pausedPerFrame), formatQUILDaily(leavingPerFrame))
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
	availTitle := fmt.Sprintf(" Available Shards (%d)", len(m.sortedAvailable()))
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

	// Actions line (key bindings, sort hint, or filter UI).
	var actionsLine, statusLine string
	switch {
	case m.filterEditActive:
		actionsLine, statusLine = m.renderFilterEditLines()
	case m.isFilterModeActive():
		colIdx := m.activeFilterColIdx()
		colName := ""
		if m.focus == allocationsPanel && colIdx >= 0 && colIdx < len(allocColNames) {
			colName = allocColNames[colIdx]
		} else if m.focus == availablePanel && colIdx >= 0 && colIdx < len(availColNames) {
			colName = availColNames[colIdx]
		}
		actionsLine = lipgloss.NewStyle().Foreground(mFilterColor).Bold(true).Render(
			fmt.Sprintf("Filter [%s]: [←/→] Column  [Enter] Edit  [Del] Clear  [x] Disable all  [Esc] Close", colName),
		)
		if m.actionInFlight {
			statusLine = m.spinner.View() + " " + m.statusMsg
		} else if m.statusMsg != "" {
			if m.statusIsError {
				statusLine = mStatusErrorStyle.Render(m.statusMsg)
			} else {
				statusLine = mStatusSuccessStyle.Render(m.statusMsg)
			}
		}
	case m.sortMode && m.sortOrderMode:
		actionsLine = lipgloss.NewStyle().Foreground(mPrimaryColor).Bold(true).Render(
			"Sort order: [Enter/a] Ascending (default)  [d] Descending  [Esc] Cancel",
		)
	case m.sortMode:
		actionsLine = lipgloss.NewStyle().Foreground(mPrimaryColor).Bold(true).Render(
			"Sort: [←/→] Move column  [Enter] Confirm  [Esc] Cancel",
		)
	default:
		actionsLine = m.renderHelpLine()
		if m.actionInFlight {
			statusLine = m.spinner.View() + " " + m.statusMsg
		} else if m.statusMsg != "" {
			if m.statusIsError {
				statusLine = mStatusErrorStyle.Render(m.statusMsg)
			} else {
				statusLine = mStatusSuccessStyle.Render(m.statusMsg)
			}
		}
	}
	doc.WriteString(mFooterStyle.Width(m.width).Render(actionsLine))
	doc.WriteString("\n")
	doc.WriteString(mFooterStyle.Width(m.width).Render(statusLine))

	return doc.String()
}

// renderFilterEditLines returns the (actionsLine, statusLine) pair rendered during filter editing.
func (m manageModel) renderFilterEditLines() (string, string) {
	colName := ""
	if m.focus == allocationsPanel && m.filterEditColIdx < len(allocColNames) {
		colName = allocColNames[m.filterEditColIdx]
	} else if m.focus == availablePanel && m.filterEditColIdx < len(availColNames) {
		colName = availColNames[m.filterEditColIdx]
	}

	kind := m.activeFilterColKind(m.filterEditColIdx)

	if kind == filterColSelect {
		// Show horizontal toggle list with cursor indicator.
		var itemParts []string
		for i, v := range m.filterEditSelectItems {
			checked := "[ ]"
			if m.filterEditSelectState[v] {
				checked = "[x]"
			}
			item := fmt.Sprintf("%s %s", checked, v)
			if i == m.filterEditSelectCursor {
				item = lipgloss.NewStyle().Foreground(mFilterColor).Bold(true).Render("▶" + item)
			} else {
				item = lipgloss.NewStyle().Foreground(mHelpColor).Render("  " + item)
			}
			itemParts = append(itemParts, item)
		}
		actionsLine := fmt.Sprintf("Filter [%s]: %s", colName, strings.Join(itemParts, "  "))
		statusLine := lipgloss.NewStyle().Foreground(mHelpColor).Render(
			"←/→: navigate  Space: toggle  a: all/none  Enter: apply  Esc: cancel",
		)
		return actionsLine, statusLine
	}

	// Text or numeric input.
	cursor := lipgloss.NewStyle().Foreground(mFilterColor).Render("_")
	actionsLine := lipgloss.NewStyle().Foreground(mFilterColor).Bold(true).Render(
		fmt.Sprintf("Filter [%s]: %s%s", colName, m.filterEditInput, cursor),
	)
	hint := "Enter: apply  Esc: cancel"
	if kind == filterColNumeric {
		hint = "Numeric: >N  >=N  <N  <=N  =N  or  N1,N2,...    " + hint
	}
	statusLine := lipgloss.NewStyle().Foreground(mHelpColor).Render(hint)
	return actionsLine, statusLine
}

func (m manageModel) renderAllocationsPanel(width, height int) string {
	sorted := m.sortedAllocations()
	if len(sorted) == 0 {
		return "  No allocations"
	}

	// Dynamic filter column width based on available space.
	// Each active filter on a non-filter column adds a '*' (1 char) to that column's
	// header; compensate by reducing fw so total layout width stays constant.
	fw := width - allocFixedWidth
	for _, colIdx := range allocFilterableCols {
		if colIdx == 1 {
			continue
		}
		if cf, ok := m.allocColFilters[colIdx]; ok && cf.isActive() {
			fw--
		}
	}
	if fw < minFilterWidth {
		fw = minFilterWidth
	}
	if fw > FILTER_WIDTH {
		fw = FILTER_WIDTH
	}

	// Build column header with sort indicators, filter markers, and highlighting.
	allocColWidths := []int{SELECT_WIDTH, fw, PROVERS_WIDTH, RING_WIDTH, SIZE_WIDTH, SHARDS_WIDTH, REWARD_WIDTH, WORKER_WIDTH, STATUS_WIDTH, MODE_WIDTH, NEXT_ACTION_WIDTH, DEFAULT_ACTION_WIDTH}
	// Add 1 to each filtered non-filter column to fit the '*' suffix.
	for _, colIdx := range allocFilterableCols {
		if colIdx == 1 {
			continue
		}
		if cf, ok := m.allocColFilters[colIdx]; ok && cf.isActive() {
			allocColWidths[colIdx]++
		}
	}
	if m.allocSortCol >= 0 && m.allocSortCol < len(allocColWidths) {
		allocColWidths[m.allocSortCol] += 2
	}
	filterHighlightCol := m.activeFilterColIdx() // -1 when not in filter mode
	var hdrParts []string
	for i, name := range allocColNames {
		w := allocColWidths[i]
		displayName := name
		// '*' suffix when a custom filter is active for this column.
		if cf, ok := m.allocColFilters[i]; ok && cf.isActive() {
			displayName = name + "*"
		}
		if m.allocSortCol == i {
			indicator := "^|"
			if !m.allocSortAsc {
				indicator = "v|"
			}
			displayName = indicator + displayName
		}
		cell := fmt.Sprintf("%*s", w, displayName)
		switch {
		case m.sortMode && m.focus == allocationsPanel && m.sortHighlightCol == i:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Background(mPrimaryColor).Foreground(mTextColor).Render(cell))
		case m.allocFilterMode && !m.filterEditActive && m.focus == allocationsPanel && filterHighlightCol == i:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Background(mFilterColor).Foreground(mTextColor).Render(cell))
		default:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Render(cell))
		}
	}
	lines := []string{strings.Join(hdrParts, " ")}

	// Compute visible window.
	visibleRows := height - 1 // minus header
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.allocOffset = clampOffset(m.allocOffset, m.allocCursor, visibleRows, len(sorted))

	end := m.allocOffset + visibleRows
	if end > len(sorted) {
		end = len(sorted)
	}

	for i := m.allocOffset; i < end; i++ {
		a := sorted[i]
		modeStr := "A"
		if a.manuallyManaged {
			modeStr = "M"
		}
		marker := "[ ]"
		if m.allocSelected[a.filterKey] {
			marker = "[x]"
		}
		workerStr := strconv.Itoa(a.workerID) // -1 for no worker assigned
		selected := i == m.allocCursor && m.focus == allocationsPanel
		var line string
		if selected {
			line = fmt.Sprintf("%"+strconv.Itoa(allocColWidths[0])+"s %"+strconv.Itoa(allocColWidths[1])+"s %"+strconv.Itoa(allocColWidths[2])+"d %"+strconv.Itoa(allocColWidths[3])+"d "+
				"%"+strconv.Itoa(allocColWidths[4])+"s %"+strconv.Itoa(allocColWidths[5])+"d %"+strconv.Itoa(allocColWidths[6])+"s %"+strconv.Itoa(allocColWidths[7])+"s %"+strconv.Itoa(allocColWidths[8])+"s "+
				"%"+strconv.Itoa(allocColWidths[9])+"s %"+strconv.Itoa(allocColWidths[10])+"s %"+strconv.Itoa(allocColWidths[11])+"s",
				marker,
				centerTrunc(a.filterHex, fw),
				a.activeProvers,
				a.ring,
				fmt.Sprintf("%.1f", float64(a.shardSize.Uint64())/float64(1024*1024)),
				a.dataShards,
				"~"+formatQUIL(a.estimatedReward),
				workerStr,
				a.statusName,
				modeStr,
				a.nextAction,
				a.defaultAction,
			)
			line = mSelectedStyle.Width(width).Render(line)
		} else {
			ringCell := fmt.Sprintf("%"+strconv.Itoa(allocColWidths[3])+"d", a.ring)
			statusCell := fmt.Sprintf("%"+strconv.Itoa(allocColWidths[8])+"s", a.statusName)
			modeCell := fmt.Sprintf("%"+strconv.Itoa(allocColWidths[9])+"s", modeStr)
			if m.colorCoding {
				ringCell = ringStyle(a.ring).Render(ringCell)
				statusCell = statusStyle(a.statusName).Render(statusCell)
				modeCell = modeStyle(modeStr).Render(modeCell)
			}
			cells := []string{
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[0])+"s", marker),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[1])+"s", centerTrunc(a.filterHex, fw)),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[2])+"d", a.activeProvers),
				ringCell,
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[4])+"s", fmt.Sprintf("%.1f", float64(a.shardSize.Uint64())/float64(1024*1024))),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[5])+"d", a.dataShards),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[6])+"s", "~"+formatQUIL(a.estimatedReward)),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[7])+"s", workerStr),
				statusCell,
				modeCell,
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[10])+"s", a.nextAction),
				fmt.Sprintf("%"+strconv.Itoa(allocColWidths[11])+"s", a.defaultAction),
			}
			line = strings.Join(cells, " ")
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func (m manageModel) renderAvailablePanel(width, height int) string {
	sorted := m.sortedAvailable()
	if len(sorted) == 0 {
		return "  No available shards"
	}

	fw := width - availFixedWidth
	for _, colIdx := range availFilterableCols {
		if colIdx == 1 {
			continue
		}
		if cf, ok := m.availColFilters[colIdx]; ok && cf.isActive() {
			fw--
		}
	}
	if fw < minFilterWidth {
		fw = minFilterWidth
	}
	if fw > FILTER_WIDTH {
		fw = FILTER_WIDTH
	}

	// Build column header with sort indicators, filter markers, and highlighting.
	availColWidths := []int{SELECT_WIDTH, fw, PROVERS_WIDTH, RING_WIDTH, SIZE_WIDTH, SHARDS_WIDTH, REWARD_WIDTH}
	for _, colIdx := range availFilterableCols {
		if colIdx == 1 {
			continue
		}
		if cf, ok := m.availColFilters[colIdx]; ok && cf.isActive() {
			availColWidths[colIdx]++
		}
	}
	if m.availSortCol >= 0 && m.availSortCol < len(availColWidths) {
		availColWidths[m.availSortCol] += 2
	}
	filterHighlightCol := m.activeFilterColIdx()
	var hdrParts []string
	for i, name := range availColNames {
		w := availColWidths[i]
		displayName := name
		if cf, ok := m.availColFilters[i]; ok && cf.isActive() {
			displayName = name + "*"
		}
		if m.availSortCol == i {
			indicator := "^|"
			if !m.availSortAsc {
				indicator = "v|"
			}
			displayName = indicator + displayName
		}
		cell := fmt.Sprintf("%*s", w, displayName)
		switch {
		case m.sortMode && m.focus == availablePanel && m.sortHighlightCol == i:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Background(mPrimaryColor).Foreground(mTextColor).Render(cell))
		case m.availFilterMode && !m.filterEditActive && m.focus == availablePanel && filterHighlightCol == i:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Background(mFilterColor).Foreground(mTextColor).Render(cell))
		default:
			hdrParts = append(hdrParts, lipgloss.NewStyle().Bold(true).Render(cell))
		}
	}
	lines := []string{strings.Join(hdrParts, " ")}

	visibleRows := height - 1
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.availOffset = clampOffset(m.availOffset, m.availCursor, visibleRows, len(sorted))

	end := m.availOffset + visibleRows
	if end > len(sorted) {
		end = len(sorted)
	}

	for i := m.availOffset; i < end; i++ {
		s := sorted[i]
		var line string
		marker := "[ ]"
		if m.availSelected[s.filterKey] {
			marker = "[x]"
		}
		if i == m.availCursor && m.focus == availablePanel {
			line = fmt.Sprintf("%"+strconv.Itoa(availColWidths[0])+"s %"+strconv.Itoa(availColWidths[1])+"s %"+strconv.Itoa(availColWidths[2])+"d %"+strconv.Itoa(availColWidths[3])+"d %"+strconv.Itoa(availColWidths[4])+"s %"+strconv.Itoa(availColWidths[5])+"d %"+strconv.Itoa(availColWidths[6])+"s",
				marker,
				centerTrunc(s.filterHex, fw),
				s.activeProvers,
				s.ring,
				fmt.Sprintf("%.1f", float64(s.shardSize.Uint64())/float64(1024*1024)),
				s.dataShards,
				"~"+formatQUIL(s.estimatedReward),
			)
			line = mSelectedStyle.Width(width).Render(line)
		} else {
			ringCell := fmt.Sprintf("%"+strconv.Itoa(availColWidths[3])+"d", s.ring)
			if m.colorCoding {
				ringCell = ringStyle(s.ring).Render(ringCell)
			}
			cells := []string{
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[0])+"s", marker),
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[1])+"s", centerTrunc(s.filterHex, fw)),
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[2])+"d", s.activeProvers),
				ringCell,
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[4])+"s", fmt.Sprintf("%.1f", float64(s.shardSize.Uint64())/float64(1024*1024))),
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[5])+"d", s.dataShards),
				fmt.Sprintf("%"+strconv.Itoa(availColWidths[6])+"s", "~"+formatQUIL(s.estimatedReward)),
			}
			line = strings.Join(cells, " ")
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

// handleJoinPickerKey processes keys while the join worker picker is active.
func (m manageModel) handleJoinPickerKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	enterKey := key.NewBinding(key.WithKeys("enter"))
	escKey := key.NewBinding(key.WithKeys("esc"))

	switch {
	case key.Matches(msg, m.keyMap.Up):
		if m.joinPickerCursor > 0 {
			m.joinPickerCursor--
		}

	case key.Matches(msg, m.keyMap.Down):
		if m.joinPickerCursor < len(m.joinPickerWorkers)-1 {
			m.joinPickerCursor++
		}

	case key.Matches(msg, m.keyMap.Select): // space
		if m.joinPickerCursor < len(m.joinPickerWorkers) {
			wid := m.joinPickerWorkers[m.joinPickerCursor]
			if m.joinPickerSelected[wid] {
				delete(m.joinPickerSelected, wid)
			} else {
				m.joinPickerSelected[wid] = true
			}
		}

	case key.Matches(msg, m.keyMap.Join), key.Matches(msg, enterKey):
		// Confirm: collect selected worker IDs, do join + mark.
		var workerIDs []uint32
		for wid := range m.joinPickerSelected {
			workerIDs = append(workerIDs, wid)
		}
		m.joinPickerActive = false
		m.actionInFlight = true
		m.statusMsg = fmt.Sprintf("Joining %d shard(s) (VDF may take a while)...", len(m.joinPickerFilters))
		m.statusIsError = false
		m.availSelected = make(map[string]bool)

		cmds := []tea.Cmd{doJoin(m.client, m.joinPickerFilters)}
		if len(workerIDs) > 0 {
			cmds = append(cmds, doMarkWorkersManual(m.client, workerIDs))
		}
		return m, tea.Batch(cmds...)

	case key.Matches(msg, escKey), key.Matches(msg, m.keyMap.Quit):
		m.joinPickerActive = false
		m.statusMsg = "Join cancelled"
		m.statusIsError = false
	}

	return m, nil
}

// renderJoinPicker draws the worker selection screen for manual-mode marking.
func (m manageModel) renderJoinPicker() string {
	var doc strings.Builder

	doc.WriteString(mHeaderStyle.Width(m.width).Render(" Select workers to mark as manually managed"))
	doc.WriteString("\n\n")
	doc.WriteString(fmt.Sprintf("  Joining %d shard(s). Select which free workers to set to Manual mode:\n\n", len(m.joinPickerFilters)))

	// header(1) + blank(1) + description(1) + blank(1) + footer blank(1) + footer(1) = 6
	visibleRows := m.height - 6
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.joinPickerOffset = clampOffset(m.joinPickerOffset, m.joinPickerCursor, visibleRows, len(m.joinPickerWorkers))

	end := m.joinPickerOffset + visibleRows
	if end > len(m.joinPickerWorkers) {
		end = len(m.joinPickerWorkers)
	}

	for i := m.joinPickerOffset; i < end; i++ {
		wid := m.joinPickerWorkers[i]
		marker := "[ ]"
		if m.joinPickerSelected[wid] {
			marker = "[x]"
		}
		cursor := "  "
		if i == m.joinPickerCursor {
			cursor = "> "
		}
		line := fmt.Sprintf("%s%s Worker %d", cursor, marker, wid)
		if i == m.joinPickerCursor {
			line = mSelectedStyle.Render(line)
		}
		doc.WriteString(line)
		doc.WriteString("\n")
	}

	doc.WriteString("\n")
	doc.WriteString(mFooterStyle.Render("  space: toggle  J/enter: confirm join  esc: cancel"))

	return doc.String()
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

// centerTrunc shortens h to maxWidth by eliding the middle with "...".
func centerTrunc(h string, maxWidth int) string {
	if maxWidth <= 3 {
		if len(h) > maxWidth {
			return h[:maxWidth]
		}
		return h
	}
	if len(h) <= maxWidth {
		return h
	}
	prefix := (maxWidth - 3) / 2
	suffix := maxWidth - 3 - prefix
	return h[:prefix] + "..." + h[len(h)-suffix:]
}

// truncHex shortens a hex string for use in short status messages.
func truncHex(h string) string {
	return centerTrunc(h, 20)
}

// fetchRPCData calls GetNodeInfo, GetShardInfo, and GetWorkerInfo.
func fetchRPCData(client protobufs.NodeServiceClient) (*protobufs.NodeInfoResponse, *protobufs.GetShardInfoResponse, *protobufs.WorkerInfoResponse, error) {
	nodeInfo, err := client.GetNodeInfo(
		context.Background(),
		&protobufs.GetNodeInfoRequest{},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GetNodeInfo: %w", err)
	}

	shardInfo, err := client.GetShardInfo(
		context.Background(),
		&protobufs.GetShardInfoRequest{IncludeAll: true},
	)
	if err != nil {
		// Shard info is optional - we can still show allocations.
		shardInfo = nil
	}

	workerInfo, err := client.GetWorkerInfo(
		context.Background(),
		&protobufs.GetWorkerInfoRequest{},
	)
	if err != nil {
		workerInfo = nil
	}

	return nodeInfo, shardInfo, workerInfo, nil
}
