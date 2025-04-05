package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

var (
	textColor      = lipgloss.Color("#fff")
	primaryColor   = lipgloss.Color("#ff0070")
	secondaryColor = lipgloss.Color("#ff5c00")
	windowHeader   = lipgloss.NewStyle().
			Foreground(textColor).
			Padding(0, 1)
	unselectedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Width(28).
				Padding(0, 1)
	navigatedListStyle = lipgloss.NewStyle().
				Foreground(textColor).
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

type model struct {
	filters          []string
	cursor           int
	selectedFilter   string
	conn             *grpc.ClientConn
	client           protobufs.NodeServiceClient
	peerId           string
	errorMsg         string
	frame            *protobufs.ClockFrame
	frames           []*protobufs.ClockFrame
	frameIndex       int
	grpcWarn         bool
	committed        bool
	lastChecked      int64
	owned            *big.Int
	unconfirmedOwned *big.Int
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.conn.GetState() == connectivity.Ready {
		if m.lastChecked < (time.Now().UnixMilli() - 10_000) {
			m.lastChecked = time.Now().UnixMilli()

			tokenBalance, err := FetchTokenBalance(m.client)
			if err == nil {
				m.owned = tokenBalance.Owned
				m.unconfirmedOwned = tokenBalance.UnconfirmedOwned
			}
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
			}
		case "down", "s":
			if m.cursor < len(m.filters)-1 {
				m.cursor++
			}
		case "left", "a":
			m.committed = false
			m.errorMsg = ""
			if m.frameIndex > 0 {
				m.frameIndex--
				if len(m.frames) != 0 && m.conn.GetState() == connectivity.Ready {
					filter, _ := hex.DecodeString(m.selectedFilter)
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = hex.EncodeToString(
								selector.FillBytes(make([]byte, 32)),
							) + ":" + err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				} else {
					m.errorMsg = "Not currently connected to node, cannot query."
				}
			} else {
				first := uint64(0)
				if len(m.frames) != 0 {
					first = m.frames[0].FrameNumber - 1
				}

				if first == 0 {
					break
				}

				max := uint64(17)
				if len(m.frames) != 0 {
					max = first
				}

				min := max - 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max + 1,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = len(m.frames) - 1
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			}
		case "right", "d":
			m.committed = false
			m.errorMsg = ""
			if m.frameIndex < len(m.frames)-1 {
				m.frameIndex++
				if len(m.frames) != 0 && m.conn.GetState() == connectivity.Ready {
					filter, _ := hex.DecodeString(m.selectedFilter)
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = hex.EncodeToString(
								selector.FillBytes(make([]byte, 32)),
							) + ":" + err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				} else {
					m.errorMsg = "Not currently connected to node, cannot query."
				}
			} else {
				min := uint64(1)
				if len(m.frames) != 0 {
					min = m.frames[len(m.frames)-1].FrameNumber + 1
				}

				max := min + 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = 0
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			}
		case "enter", " ":
			m.errorMsg = ""
			m.frame = nil
			m.committed = false
			if m.conn.GetState() == connectivity.Ready {
				if m.selectedFilter != m.filters[m.cursor] {
					m.selectedFilter = m.filters[m.cursor]
					m.frames = []*protobufs.ClockFrame{}
				}

				min := uint64(1)
				if len(m.frames) != 0 {
					min = m.frames[len(m.frames)-1].FrameNumber + 1
				}

				max := min + 16
				filter, _ := hex.DecodeString(m.selectedFilter)
				frames, err := m.client.GetFrames(
					context.Background(),
					&protobufs.GetFramesRequest{
						Filter:            filter,
						FromFrameNumber:   min,
						ToFrameNumber:     max,
						IncludeCandidates: true,
					},
				)
				if err != nil {
					m.selectedFilter = ""
					m.errorMsg = err.Error()
					break
				}

				if frames.TruncatedClockFrames != nil {
					m.frames = frames.TruncatedClockFrames
					m.frameIndex = 0
					selector, err := m.frames[m.frameIndex].GetSelector()
					if err != nil {
						m.errorMsg = err.Error()
						break
					}

					frameInfo, err := m.client.GetFrameInfo(
						context.Background(),
						&protobufs.GetFrameInfoRequest{
							Filter:      filter,
							FrameNumber: m.frames[m.frameIndex].FrameNumber,
						},
					)
					if err == nil && bytes.Equal(
						frameInfo.ClockFrame.Output,
						m.frames[m.frameIndex].Output,
					) {
						m.committed = true
						m.frame = frameInfo.ClockFrame
					} else {
						frameInfo, err := m.client.GetFrameInfo(
							context.Background(),
							&protobufs.GetFrameInfoRequest{
								Filter:      filter,
								FrameNumber: m.frames[m.frameIndex].FrameNumber,
								Selector:    selector.FillBytes(make([]byte, 32)),
							},
						)
						if err != nil {
							m.errorMsg = err.Error()
							break
						}
						m.frame = frameInfo.ClockFrame
					}
				}
			} else {
				m.errorMsg = "Not currently connected to node, cannot query."
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	logger := utils.GetLogger().With(zap.String("stage", "db-console-view-model"))
	physicalWidth, physicalHeight, _ := term.GetSize(int(os.Stdout.Fd()))
	doc := strings.Builder{}

	window := lipgloss.NewStyle().
		Border(border, true).
		BorderForeground(primaryColor).
		Padding(0, 1)

	list := []string{}
	for i, item := range m.filters {
		str := item[0:12] + ".." + item[len(item)-12:]
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

	ownedVal := statusItemStyle.Copy().
		Render("Owned: " + m.owned.String())
	if m.owned.Cmp(big.NewInt(-1)) == 0 {
		ownedVal = statusItemStyle.Copy().
			Render("")
	}

	unconfirmedOwnedVal := statusItemStyle.Copy().
		Render("Unconfirmed: " + m.unconfirmedOwned.String())
	if m.unconfirmedOwned.Cmp(big.NewInt(-1)) == 0 {
		unconfirmedOwnedVal = statusItemStyle.Copy().
			Render("")
	}
	peerIdVal := statusItemStyle.Render(m.peerId)
	statusVal := statusBarStyle.Copy().
		Width(physicalWidth-w(statusKey)-w(info)-w(peerIdVal)-w(ownedVal)-
			w(unconfirmedOwnedVal)).
		Padding(0, 1).
		Render(onlineStatus)

	bar := lipgloss.JoinHorizontal(lipgloss.Top,
		statusKey,
		statusVal,
		info,
		peerIdVal,
		ownedVal,
		unconfirmedOwnedVal,
	)

	explorerContent := ""

	if m.errorMsg != "" {
		explorerContent = m.errorMsg
	} else if m.frame != nil {
		selector, err := m.frame.GetSelector()
		if err != nil {
			logger.Panic("error getting selector", zap.Error(err))
		}
		committed := "Unconfirmed"
		if m.committed {
			committed = "Confirmed"
		}
		explorerContent = fmt.Sprintf(
			"Frame %d (Selector: %x, %s):\n\tParent: %x\n\tVDF Proof: %x\n",
			m.frame.FrameNumber,
			selector.FillBytes(make([]byte, 32)),
			committed,
			m.frame.ParentSelector,
			m.frame.Input[:516],
		)

		for i := 0; i < len(m.frame.Input[516:])/74; i++ {
			commit := m.frame.Input[516+(i*74) : 516+((i+1)*74)]
			explorerContent += fmt.Sprintf(
				"\tCommitment %+x\n",
				commit,
			)
			explorerContent += fmt.Sprintf(
				"\t\tType: %s\n",
				m.frame.AggregateProofs[i].InclusionCommitments[0].TypeUrl,
			)
		}
	} else {
		explorerContent = logoVersion(physicalWidth - 34)
	}

	doc.WriteString(
		lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.JoinHorizontal(
				lipgloss.Top,
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Filters (Up/Down, Enter)"),
					window.Width(30).Height(physicalHeight-4).Render(lipgloss.JoinVertical(lipgloss.Left, list...)),
				),
				lipgloss.JoinVertical(
					lipgloss.Left,
					windowHeader.Render("Explorer (Left/Right)"),
					window.Width(physicalWidth-34).Height(physicalHeight-4).Render(explorerContent),
				),
			),
			statusBarStyle.Width(physicalWidth).Render(bar),
		),
	)

	if physicalWidth > 0 {
		docStyle = docStyle.MaxWidth(physicalWidth)
		docStyle = docStyle.MaxHeight(physicalHeight)
	}

	return docStyle.Render(doc.String())
}

func consoleModel(
	conn *grpc.ClientConn,
	nodeConfig *config.Config,
	grpcWarn bool,
) model {
	logger := utils.GetLogger()
	peerPrivKey, err := hex.DecodeString(nodeConfig.P2P.PeerPrivKey)
	if err != nil {
		logger.Panic("error decode peer private key", zap.Error(err))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		logger.Panic("error getting peer id", zap.Error(err))
	}

	return model{
		filters: []string{
			hex.EncodeToString([]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}),
		},
		cursor:           0,
		conn:             conn,
		client:           protobufs.NewNodeServiceClient(conn),
		owned:            big.NewInt(-1),
		unconfirmedOwned: big.NewInt(-1),
		peerId:           id.String(),
		grpcWarn:         grpcWarn,
	}
}

var defaultGrpcAddress = "localhost:8337"

// Connect to the node via GRPC
func ConnectToNode(nodeConfig *config.Config) (*grpc.ClientConn, error) {
	logger := utils.GetLogger().With(zap.String("stage", "db-console-connect-to-node"))
	addr := defaultGrpcAddress
	if nodeConfig.ListenGRPCMultiaddr != "" {
		ma, err := multiaddr.NewMultiaddr(nodeConfig.ListenGRPCMultiaddr)
		if err != nil {
			logger.Panic("error parsing multiaddr", zap.Error(err))
		}

		_, addr, err = mn.DialArgs(ma)
		if err != nil {
			logger.Panic("error getting dial args", zap.Error(err))
		}
	}

	return qgrpc.DialContext(
		context.Background(),
		addr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		),
	)
}

type TokenBalance struct {
	Owned            *big.Int
	UnconfirmedOwned *big.Int
}

func FetchTokenBalance(client protobufs.NodeServiceClient) (TokenBalance, error) {
	info, err := client.GetTokenInfo(
		context.Background(),
		&protobufs.GetTokenInfoRequest{},
	)
	if err != nil {
		return TokenBalance{}, errors.Wrap(err, "error getting token info")
	}

	owned := new(big.Int).SetBytes(info.OwnedTokens)

	return TokenBalance{
		Owned: owned,
	}, nil
}

func FetchNodeInfo(client protobufs.NodeServiceClient) (*protobufs.NodeInfoResponse, error) {
	info, err := client.GetNodeInfo(
		context.Background(),
		&protobufs.GetNodeInfoRequest{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "error getting node info")
	}

	return info, nil
}

// Runs the DB console
func (c *DBConsole) Run() {
	logger := utils.GetLogger().With(zap.String("stage", "db-console-run"))
	conn, err := ConnectToNode(c.nodeConfig)
	if err != nil {
		logger.Panic("error connecting to node", zap.Error(err))
	}
	defer conn.Close()

	grpcWarn := c.nodeConfig.ListenGRPCMultiaddr == ""

	p := tea.NewProgram(consoleModel(conn, c.nodeConfig, grpcWarn))
	if _, err := p.Run(); err != nil {
		logger.Panic("error running program", zap.Error(err))
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
		out += "                       Quilibrium Node - v" + config.GetVersionString() + " – Dusk\n"
		out += " \n"
		out += "                                   DB Console\n"
	} else {
		out = "Quilibrium Node - v" + config.GetVersionString() + " – Dusk - DB Console\n"
	}
	return out
}
