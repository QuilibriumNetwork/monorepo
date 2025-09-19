package onion

const (
	CellSize = 512 // fixed-size cells at the link layer

	// Relay commands
	CmdPadding         byte = 0x00
	CmdBegin           byte = 0x01 // open a stream to addr (like Tor BEGIN)
	CmdData            byte = 0x02 // payload bytes
	CmdEnd             byte = 0x03 // half/close
	CmdSendMe          byte = 0x04 // simple flow control (credit)
	CmdExtend          byte = 0x05 // initiates an extend call
	CmdExtended        byte = 0x06 // reply to an extend call
	CmdIntroEstablish  byte = 0x07 // service -> intro relay: register as intro point
	CmdIntroAck        byte = 0x08 // intro relay -> service: ack establish
	CmdIntroduce       byte = 0x09 // client -> intro relay (relayed to service): carry rendezvous info
	CmdRend1           byte = 0x0A // client -> rendezvous relay: register cookie + client SID
	CmdRend2           byte = 0x0B // service -> rendezvous relay: complete cookie + service SID
	CmdRendEstablished byte = 0x0C // rendezvous -> both: splice confirmed

	// Link commands
	CmdCreate  = 0xA0 // initiates a create call
	CmdCreated = 0xA1 // reply to a create call
)

// TODO(2.2+): MPCTLS differentiates, we would need additional protocol flag
// for exit nodes with support
const ProtocolRouting uint32 = 0x00000301
const DefaultOnionKeyPurpose = "ONION_ROUTING"
