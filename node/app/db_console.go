package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/muesli/reflow/wordwrap"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
)

var (
	textColor      = lipgloss.Color("#fff")
	primaryColor   = lipgloss.Color("#ff0070")
	secondaryColor = lipgloss.Color("#ff5c00")
	windowHeader   = lipgloss.NewStyle().
			Padding(0, 1)
	unselectedListStyle = lipgloss.NewStyle().
				Width(28).
				Padding(0, 1)
	navigatedListStyle = lipgloss.NewStyle().
				Width(28).
				Bold(true).
				Padding(0, 1)
	selectedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Background(primaryColor).
				Width(28).
				Padding(0, 1)
	statusBarStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(primaryColor)
	statusStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(primaryColor).
			Padding(0, 1)
	statusItemStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 1)
	docStyle = lipgloss.NewStyle().Padding(0)
	border   = lipgloss.Border{
		Top:         "─",
		Bottom:      "─",
		Left:        "│",
		Right:       "│",
		TopLeft:     "┌",
		TopRight:    "┐",
		BottomLeft:  "└",
		BottomRight: "┘",
	}
)

type DBConsole struct {
	nodeConfig *config.Config
}

func newDBConsole(nodeConfig *config.Config) (*DBConsole, error) {
	return &DBConsole{
		nodeConfig,
	}, nil
}

// func FetchTokenBalance(nodeClient protobufs.NodeServiceClient)

type masterModel struct {
	filters        []string
	cursor         int
	selectedFilter string
	conn           *grpc.ClientConn
	globalClient   protobufs.GlobalServiceClient
	nodeClient     protobufs.NodeServiceClient
	peerId         string
	errorMsg       string
	frame          *protobufs.GlobalFrame
	frames         []*protobufs.GlobalFrame
	workers        []*protobufs.GlobalGetWorkerInfoResponseItem
	frameIndex     int
	grpcWarn       bool
	committed      bool
	lastChecked    int64
	width          int
	height         int
	owned          *big.Int
}

func (m masterModel) Init() tea.Cmd {
	return nil
}

func (m masterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.conn.GetState() == connectivity.Ready {
		if m.lastChecked < (time.Now().UnixMilli() - 10_000) {
			m.lastChecked = time.Now().UnixMilli()

			// tokenBalance, err := FetchTokenBalance(m.nodeClient)
			// if err == nil {
			// 	m.owned = tokenBalance
			// }
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "w":
			if m.cursor > 0 {
				m.cursor--
				m.frameIndex = 0
			}
		case "down", "s":
			if m.cursor < len(m.filters)-1 {
				m.cursor++
				m.frameIndex = 0
			}
		case "[", "a":
			m.committed = false
			m.errorMsg = ""
			if m.cursor == 0 {
				if m.frameIndex > 0 {
					m.frameIndex--
					if !(m.conn.GetState() == connectivity.Connecting || m.conn.GetState() == connectivity.Shutdown) {
						frameInfo, err := m.globalClient.GetGlobalFrame(
							context.Background(),
							&protobufs.GetGlobalFrameRequest{
								FrameNumber: uint64(m.frameIndex),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
						} else {
							m.frame = frameInfo.Frame
						}
					} else {
						m.errorMsg = "Not currently connected to node, cannot query."
					}
				} else if m.cursor == len(m.filters)-1 {
					workers, err := m.globalClient.GetWorkerInfo(
						context.Background(),
						&protobufs.GlobalGetWorkerInfoRequest{},
					)
					if err != nil {
						m.errorMsg = "Not currently connected to node, cannot query."
					} else {
						m.workers = workers.Workers
					}
				}
			}
		case "]", "d":
			m.committed = false
			m.errorMsg = ""
			m.frameIndex++
			if m.cursor == 0 {
				if !(m.conn.GetState() == connectivity.Connecting || m.conn.GetState() == connectivity.Shutdown) {
					frameInfo, err := m.globalClient.GetGlobalFrame(
						context.Background(),
						&protobufs.GetGlobalFrameRequest{
							FrameNumber: uint64(m.frameIndex),
						},
					)
					if err != nil {
						m.errorMsg = err.Error()
					} else {
						m.frame = frameInfo.Frame
					}
				} else {
					m.errorMsg = "Not currently connected to node, cannot query."
				}
			} else if m.cursor == len(m.filters)-1 {
				workers, err := m.globalClient.GetWorkerInfo(
					context.Background(),
					&protobufs.GlobalGetWorkerInfoRequest{},
				)
				if err != nil {
					m.errorMsg = "Not currently connected to node, cannot query."
				} else {
					m.workers = workers.Workers
				}
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m masterModel) View() string {
	doc := strings.Builder{}

	window := lipgloss.NewStyle().
		Border(border, true).
		BorderForeground(primaryColor).
		Padding(0, 1)

	list := []string{}
	for i, item := range m.filters {
		var str string
		if len(item) > 24 {
			str = item[0:12] + ".." + item[len(item)-12:]
		} else {
			str = item
		}
		if m.selectedFilter == item {
			list = append(list, selectedListStyle.Render(str))
		} else if i == m.cursor {
			list = append(list, navigatedListStyle.Render(str))
		} else {
			list = append(list, unselectedListStyle.Render(str))
		}
	}

	w := lipgloss.Width

	statusKey := statusItemStyle.Render("STATUS")
	info := statusStyle.Render("(Press Ctrl-C or Q to quit)")
	onlineStatus := "gRPC Not Enabled, Please Configure"
	if !m.grpcWarn {
		switch m.conn.GetState() {
		case connectivity.Connecting:
			onlineStatus = "CONNECTING"
		case connectivity.Idle:
			onlineStatus = "IDLE"
		case connectivity.Shutdown:
			onlineStatus = "SHUTDOWN"
		case connectivity.TransientFailure:
			onlineStatus = "DISCONNECTED"
		default:
			onlineStatus = "CONNECTED"
		}
	}

	ownedVal := statusItemStyle.Render("Owned: " + m.owned.String())
	if m.owned.Cmp(big.NewInt(-1)) == 0 {
		ownedVal = statusItemStyle.Render("")
	}

	peerIdVal := statusItemStyle.Render(m.peerId)
	statusVal := statusBarStyle.Copy().
		Width(m.width-w(statusKey)-w(info)-w(peerIdVal)-w(ownedVal)).
		Padding(0, 1).
		Render(onlineStatus)

	bar := lipgloss.JoinHorizontal(lipgloss.Top,
		statusKey,
		statusVal,
		info,
		peerIdVal,
		ownedVal,
	)

	explorerContent := ""

	if m.errorMsg != "" {
		explorerContent = m.errorMsg
	} else if m.frame != nil && m.cursor != len(m.filters)-1 {
		selBI, err := poseidon.HashBytes(m.frame.Header.Output)
		if err != nil {
			panic(err)
		}
		selector := selBI.FillBytes(make([]byte, 32))
		explorerContent = fmt.Sprintf(
			"Frame %d (Selector: %x):\n\tParent: %x\n\tVDF Proof: %x\n\nRequests:\n",
			m.frame.Header.FrameNumber,
			selector,
			m.frame.Header.ParentSelector,
			m.frame.Header.Output,
		)
		for _, req := range m.frame.Requests {
			for _, r := range req.Requests {
				switch fr := r.Request.(type) {
				case *protobufs.MessageRequest_Join:
					explorerContent += "\tJoin: " + hex.EncodeToString(fr.Join.GetPublicKeySignatureBls48581().PublicKey.KeyValue) + "\n"
				case *protobufs.MessageRequest_Leave:
					explorerContent += "\tLeave: " + hex.EncodeToString(fr.Leave.GetPublicKeySignatureBls48581().Address) + "\n"
				case *protobufs.MessageRequest_Pause:
					explorerContent += "\tPause: " + hex.EncodeToString(fr.Pause.GetPublicKeySignatureBls48581().Address) + "\n"
				case *protobufs.MessageRequest_Resume:
					explorerContent += "\tResume: " + hex.EncodeToString(fr.Resume.GetPublicKeySignatureBls48581().Address) + "\n"
				case *protobufs.MessageRequest_Confirm:
					explorerContent += "\tConfirm: " + hex.EncodeToString(fr.Confirm.GetPublicKeySignatureBls48581().Address) + "\n"
				case *protobufs.MessageRequest_Reject:
					explorerContent += "\tReject: " + hex.EncodeToString(fr.Reject.GetPublicKeySignatureBls48581().Address) + "\n"
				case *protobufs.MessageRequest_Kick:
					explorerContent += "\tKick: " + hex.EncodeToString(fr.Kick.KickedProverPublicKey) + "\n"
				case *protobufs.MessageRequest_Update:
					explorerContent += "\tUpdate: " + hex.EncodeToString(fr.Update.GetPublicKeySignatureBls48581().Address) + "\n"
				}
			}
		}
	} else if len(m.workers) != 0 && m.cursor == len(m.filters)-1 {
		explorerContent = "Workers:\n"
		for _, worker := range m.workers {
			explorerContent += fmt.Sprintf(
				"\tWorker %d:\n\t\tFilter: %s\n\t\tAllocated: %v\n",
				worker.CoreId,
				worker.Filter,
				worker.Allocated,
			)
		}
	} else {
		explorerContent = logoVersion(m.width - 34)
	}

	doc.WriteString(
		lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.JoinHorizontal(
				lipgloss.Top,
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Filters (Up/Down, Enter)"),
					window.Width(30).Height(m.height-4).Render(
						lipgloss.JoinVertical(lipgloss.Left, list...),
					),
				),
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Explorer ([/])"),
					window.Width(m.width-34).Height(m.height-4).Render(
						explorerContent,
					),
				),
			),
			statusBarStyle.Width(m.width).Render(bar),
		),
	)

	if m.width > 0 {
		docStyle = docStyle.MaxWidth(m.width)
		docStyle = docStyle.MaxHeight(m.height)
	}

	return docStyle.Render(doc.String())
}

func consoleModel(
	nodeConfig *config.Config,
	grpcWarn bool,
) masterModel {
	peerPrivKey, err := hex.DecodeString(nodeConfig.P2P.PeerPrivKey)
	if err != nil {
		log.Fatal("error decode peer private key", err)
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		log.Fatal("error unmarshaling peerkey", err)
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		log.Fatal("error getting peer id", err)
	}
	addr, err := multiaddr.StringCast(nodeConfig.P2P.StreamListenMultiaddr)
	if err != nil {
		log.Fatal(err)
	}

	mga, err := mn.ToNetAddr(addr)
	if err != nil {
		log.Fatal(err)
	}

	creds, err := p2p.NewPeerAuthenticator(
		zap.NewNop(),
		nodeConfig.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(id)},
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.global.pb.GlobalService": channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(id))
	if err != nil {
		log.Fatal(err)
	}

	client, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		log.Fatal(err)
	}

	globalClient := protobufs.NewGlobalServiceClient(client)

	filters := []string{
		hex.EncodeToString([]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}),
	}

	filters = append(filters, "worker info")

	return masterModel{
		filters:      filters,
		cursor:       0,
		conn:         client,
		globalClient: globalClient,
		nodeClient:   protobufs.NewNodeServiceClient(client),
		owned:        big.NewInt(-1),
		peerId:       id.String(),
		grpcWarn:     grpcWarn,
	}
}

var defaultGrpcAddress = "localhost:8337"

type tailSpec struct {
	Title string // tab title
	Path  string // file path
}

type model struct {
	console  tea.Model
	tabs     []tailSpec
	config   *config.Config
	active   int
	vps      []*viewport.Model
	bufs     []strings.Builder
	offsets  []int64
	wrapped  []string
	err      error
	width    int
	height   int
	ready    bool
	lastTick time.Time
}

type tickMsg time.Time
type fileChunkMsg struct {
	idx   int
	chunk string
	err   error
}

func pollInterval() time.Duration { return 1 * time.Second }

// Tail N files; read any new bytes since last offset and send as msg.
func tailCmd(idx int, path string, offset int64) tea.Cmd {
	return func() tea.Msg {
		f, err := os.Open(path)
		if err != nil {
			// Not fatal; often file appears later
			return fileChunkMsg{idx: idx, err: err}
		}
		defer f.Close()

		// Seek to last offset
		st, statErr := f.Stat()
		if statErr != nil {
			return fileChunkMsg{idx: idx, err: statErr}
		}
		size := st.Size()
		if size < offset {
			// rotated/truncated; start from 0
			offset = 0
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fileChunkMsg{idx: idx, err: err}
		}

		var b strings.Builder
		r := bufio.NewReader(f)
		nread := int64(0)
		for {
			s, e := r.ReadString('\n')
			if len(s) > 0 {
				b.WriteString(s)
				nread += int64(len(s))
			}
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return fileChunkMsg{idx: idx, err: e}
			}
		}
		return fileChunkMsg{idx: idx, chunk: b.String(), err: nil}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(pollInterval(), func(t time.Time) tea.Msg { return tickMsg(t) })
}

func newModel(config *config.Config, specs []tailSpec) model {
	vps := make([]*viewport.Model, len(specs))
	offsets := make([]int64, len(specs)-1)
	bufs := make([]strings.Builder, len(specs)-1)
	wrapped := make([]string, len(specs)-1)
	for i := range vps {
		v := viewport.New(0, 0)
		v.MouseWheelEnabled = true
		vps[i] = &v
	}

	return model{
		console: consoleModel(config, false),
		config:  config,
		tabs:    specs,
		active:  0,
		vps:     vps,
		offsets: offsets,
		bufs:    bufs,
		wrapped: wrapped,
	}
}

var (
	tabBorder      = lipgloss.NewStyle().Padding(0, 1)
	tabActiveStyle = lipgloss.NewStyle().Bold(true).Underline(true)
	tabStyle       = lipgloss.NewStyle().Faint(true)
	barStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

func (m model) Init() tea.Cmd {
	// start ticking and initial tail reads
	cmds := []tea.Cmd{tickCmd()}
	for i := range len(m.tabs) - 1 {
		s := m.tabs[i+1]
		cmds = append(cmds, tailCmd(i, s.Path, m.offsets[i]))
	}
	return tea.Batch(cmds...)
}

func (m *model) setSize(width, height int) {
	m.width = width
	m.height = height
	tabBarHeight := 1 + 1 // line + padding
	for _, vp := range m.vps {
		vp.Width = width
		vp.Height = height - tabBarHeight
	}
	// The first one renders the console
	m.console, _ = m.console.Update(tea.WindowSizeMsg{
		Width:  width,
		Height: height - tabBarHeight,
	})
	m.vps[0].SetContent(m.console.View())
	// Re-wrap all text buffers to the new width
	for i := range m.vps[1:] {
		raw := m.bufs[i].String()
		m.wrapped[i] = wrapToWidth(raw, m.vps[i].Width)
		m.vps[i].SetContent(m.wrapped[i])
		m.vps[i].GotoBottom()
	}

	m.ready = true
}

func wrapToWidth(s string, w int) string {
	if w <= 0 || len(s) == 0 {
		return s
	}
	// normalize CRLF/CR and ensure valid UTF-8
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return wordwrap.String(s, w)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case tea.KeyMsg:
		switch x.String() {
		case "left", "h":
			if m.active > 0 {
				m.active--
			}
			m.vps[m.active].GotoBottom()
		case "right", "l":
			if m.active < len(m.tabs)-1 {
				m.active++
			}
			m.vps[m.active].GotoBottom()
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		default:
			if m.active == 0 {
				m.console, _ = m.console.Update(x)
			}
			vp := m.vps[m.active]
			var cmd tea.Cmd
			*vp, cmd = vp.Update(x)
			return m, cmd
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.setSize(x.Width, x.Height)
	case tickMsg:
		var cmds []tea.Cmd
		m.lastTick = time.Time(x)
		cmds = append(cmds, tickCmd())
		// schedule next tick, and tail open file
		if m.active != 0 {
			s := m.tabs[m.active]
			i := m.active - 1
			cmds = append(cmds, tailCmd(i, s.Path, m.offsets[i]))
		}
		return m, tea.Batch(cmds...)
	case fileChunkMsg:
		if x.err == nil && x.chunk != "" {
			// Append to our own buffer, then set viewport content
			b := &m.bufs[x.idx]
			b.WriteString(x.chunk)
			vp := m.vps[x.idx+1]

			// If user was at bottom *before* the update, keep them pinned.
			// Otherwise, respect their scroll position.
			stickToBottom := vp.AtBottom()
			// Wrap to current width and set content
			m.wrapped[x.idx] = wrapToWidth(b.String(), vp.Width)
			vp.SetContent(m.wrapped[x.idx])

			// Update offset by bytes actually read
			m.offsets[x.idx] += int64(len(x.chunk))

			if x.idx == m.active && stickToBottom {
				vp.GotoBottom()
			}
		}
		// Non-fatal errors get displayed in status bar
		if x.err != nil && !os.IsNotExist(x.err) {
			m.err = x.err
		}
	}
	return m, nil
}

func (m model) View() string {
	// Tabs
	var parts []string
	for i, s := range m.tabs {
		label := s.Title
		style := tabStyle
		if i == m.active {
			style = tabActiveStyle
		}
		parts = append(parts, tabBorder.Render(style.Render(label)))
	}
	bar := barStyle.Render(strings.Join(parts, " "))

	// Active viewport
	body := ""
	if m.active == 0 {
		m.vps[m.active].SetContent(m.console.View())
	}
	if len(m.vps) > 0 {
		body = m.vps[m.active].View()
	}
	status := ""
	if m.err != nil {
		status = lipgloss.NewStyle().Foreground(
			lipgloss.Color("9"),
		).Render("\n" + m.err.Error())
	}
	return bar + "\n" + body + status
}

// Runs the DB console
func (c *DBConsole) Run() {
	logDir := ""
	if c.nodeConfig.Logger != nil {
		logDir = c.nodeConfig.Logger.Path
	}

	var entries []os.DirEntry
	var err error

	if logDir != "" {
		entries, err = os.ReadDir(logDir)
		if err != nil {
			fmt.Printf("failed to read log dir %s: %v\n", logDir, err)
			os.Exit(1)
		}
	}

	type workerLog struct {
		number int
		name   string
	}

	var workers []workerLog
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "worker-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(name, "worker-"), ".log")
		num, err := strconv.Atoi(numStr)
		if err != nil {
			continue
		}
		workers = append(workers, workerLog{
			number: num,
			name:   name,
		})
	}

	sort.Slice(workers, func(i, j int) bool {
		return workers[i].number < workers[j].number
	})

	specs := []tailSpec{
		{Title: "console"},
	}
	if logDir != "" {
		specs = append(
			specs,
			tailSpec{Title: "master", Path: filepath.Join(logDir, "master.log")},
		)
	}
	for _, worker := range workers {
		specs = append(specs, tailSpec{
			Title: fmt.Sprintf("worker-%d", worker.number),
			Path:  filepath.Join(logDir, worker.name),
		})
	}

	p := tea.NewProgram(
		newModel(c.nodeConfig, specs),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	if err := p.Start(); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func logoVersion(width int) string {
	var out string

	if width >= 83 {
		out = "████████████████████████████████████████████████████████████████████████████████\n"
		out += "████████████████████████████████████████████████████████████████████████████████\n"
		out += "██████████████████████████████                    ██████████████████████████████\n"
		out += "█████████████████████████                              █████████████████████████\n"
		out += "█████████████████████                                      █████████████████████\n"
		out += "██████████████████                                            ██████████████████\n"
		out += "████████████████                     ██████                     ████████████████\n"
		out += "██████████████                ████████████████████                ██████████████\n"
		out += "█████████████             ████████████████████████████              ████████████\n"
		out += "███████████            ██████████████████████████████████            ███████████\n"
		out += "██████████           ██████████████████████████████████████           ██████████\n"
		out += "█████████          ██████████████████████████████████████████          █████████\n"
		out += "████████          ████████████████████████████████████████████          ████████\n"
		out += "███████          ████████████████████      ████████████████████          ███████\n"
		out += "██████          ███████████████████          ███████████████████          ██████\n"
		out += "█████          ███████████████████            ███████████████████          █████\n"
		out += "█████         ████████████████████            ████████████████████         █████\n"
		out += "████         █████████████████████            █████████████████████         ████\n"
		out += "████         ██████████████████████          ██████████████████████         ████\n"
		out += "████        █████████████████████████      █████████████████████████        ████\n"
		out += "████        ████████████████████████████████████████████████████████        ████\n"
		out += "████        ████████████████████████████████████████████████████████        ████\n"
		out += "████        ████████████████████  ████████████  ████████████████████        ████\n"
		out += "████        ██████████████████                   ███████████████████        ████\n"
		out += "████         ████████████████                      ████████████████         ████\n"
		out += "████         ██████████████            ██            ██████████████         ████\n"
		out += "█████        ████████████            ██████            ████████████        █████\n"
		out += "█████         █████████            ██████████            █████████         █████\n"
		out += "██████         ███████           █████████████             ███████        ██████\n"
		out += "██████          ████████       █████████████████            ████████      ██████\n"
		out += "███████          █████████   █████████████████████            ████████   ███████\n"
		out += "████████           █████████████████████████████████            ████████████████\n"
		out += "█████████           ██████████████████████████████████            ██████████████\n"
		out += "██████████            ██████████████████████████████████           █████████████\n"
		out += "████████████             ████████████████████████████████            ███████████\n"
		out += "█████████████               ███████████████████████████████            █████████\n"
		out += "███████████████                 ████████████████    █████████            ███████\n"
		out += "█████████████████                                     █████████            █████\n"
		out += "████████████████████                                    █████████         ██████\n"
		out += "███████████████████████                                  ██████████     ████████\n"
		out += "███████████████████████████                          ███████████████  ██████████\n"
		out += "█████████████████████████████████              █████████████████████████████████\n"
		out += "████████████████████████████████████████████████████████████████████████████████\n"
		out += "████████████████████████████████████████████████████████████████████████████████\n"
		out += " \n"
		out += "                    Quilibrium Node - v" + config.GetVersionString() + " – Bloom\n"
		out += " \n"
		out += "                                   DB Console\n"
	} else {
		out = "Quilibrium Node - v" + config.GetVersionString() + " – Bloom - DB Console\n"
	}
	return out
}
