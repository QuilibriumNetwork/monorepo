package multiaddr

// You **MUST** register your multicodecs with
// https://github.com/multiformats/multicodec before adding them here.
const (
	P_IP4               = 4
	P_TCP               = 6
	P_DNS               = 53 // 4 or 6
	P_DNS4              = 54
	P_DNS6              = 55
	P_DNSADDR           = 56
	P_UDP               = 273
	P_DCCP              = 33
	P_IP6               = 41
	P_IP6ZONE           = 42
	P_IPCIDR            = 43
	P_QUIC              = 460
	P_QUIC_V1           = 461
	P_WEBTRANSPORT      = 465
	P_CERTHASH          = 466
	P_SCTP              = 132
	P_CIRCUIT           = 290
	P_UDT               = 301
	P_UTP               = 302
	P_UNIX              = 400
	P_P2P               = 421
	P_IPFS              = P_P2P // alias for backwards compatibility
	P_HTTP              = 480
	P_HTTP_PATH         = 481
	P_HTTPS             = 443 // deprecated alias for /tls/http
	P_ONION             = 444 // also for backwards compatibility
	P_ONION3            = 445
	P_GARLIC64          = 446
	P_GARLIC32          = 447
	P_P2P_WEBRTC_DIRECT = 276 // Deprecated. use webrtc-direct instead
	P_TLS               = 448
	P_SNI               = 449
	P_NOISE             = 454
	P_WS                = 477
	P_WSS               = 478 // deprecated alias for /tls/ws
	P_PLAINTEXTV2       = 7367777
	P_WEBRTC_DIRECT     = 280
	P_WEBRTC            = 281
	P_MEMORY            = 777
)

var (
	codeIP4, _               = CodeToVarint(P_IP4)
	codeTCP, _               = CodeToVarint(P_TCP)
	codeDNS, _               = CodeToVarint(P_DNS)
	codeDNS4, _              = CodeToVarint(P_DNS4)
	codeDNS6, _              = CodeToVarint(P_DNS6)
	codeDNSADDR, _           = CodeToVarint(P_DNSADDR)
	codeUDP, _               = CodeToVarint(P_UDP)
	codeDCCP, _              = CodeToVarint(P_DCCP)
	codeIP6, _               = CodeToVarint(P_IP6)
	codeIPCIDR, _            = CodeToVarint(P_IPCIDR)
	codeIP6ZONE, _           = CodeToVarint(P_IP6ZONE)
	codeSCTP, _              = CodeToVarint(P_SCTP)
	codeCIRCUIT, _           = CodeToVarint(P_CIRCUIT)
	codeONION2, _            = CodeToVarint(P_ONION)
	codeONION3, _            = CodeToVarint(P_ONION3)
	codeGARLIC64, _          = CodeToVarint(P_GARLIC64)
	codeGARLIC32, _          = CodeToVarint(P_GARLIC32)
	codeUTP, _               = CodeToVarint(P_UTP)
	codeUDT, _               = CodeToVarint(P_UDT)
	codeQUIC, _              = CodeToVarint(P_QUIC)
	codeQUICV1, _            = CodeToVarint(P_QUIC_V1)
	codeWEBTRANSPORT, _      = CodeToVarint(P_WEBTRANSPORT)
	codeCERTHASH, _          = CodeToVarint(P_CERTHASH)
	codeHTTP, _              = CodeToVarint(P_HTTP)
	codeHTTPPath, _          = CodeToVarint(P_HTTP_PATH)
	codeHTTPS, _             = CodeToVarint(P_HTTPS)
	codeP2P, _               = CodeToVarint(P_P2P)
	codeUNIX, _              = CodeToVarint(P_UNIX)
	codeP2P_WEBRTC_DIRECT, _ = CodeToVarint(P_P2P_WEBRTC_DIRECT)
	codeTLS, _               = CodeToVarint(P_TLS)
	codeSNI, _               = CodeToVarint(P_SNI)
	codeNOISE, _             = CodeToVarint(P_NOISE)
	codePlaintextV2, _       = CodeToVarint(P_PLAINTEXTV2)
	codeWS, _                = CodeToVarint(P_WS)
	codeWSS, _               = CodeToVarint(P_WSS)
	codeWebRTCDirect, _      = CodeToVarint(P_WEBRTC_DIRECT)
	codeWebRTC, _            = CodeToVarint(P_WEBRTC)
	codeMemory, _ 		 = CodeToVarint(P_MEMORY)
	protoIP4                 = Protocol{
		Name:       "ip4",
		Code:       P_IP4,
		VCode:      codeIP4,
		Size:       32,
		Path:       false,
		Transcoder: TranscoderIP4,
	}
	protoTCP = Protocol{
		Name:       "tcp",
		Code:       P_TCP,
		VCode:      codeTCP,
		Size:       16,
		Path:       false,
		Transcoder: TranscoderPort,
	}
	protoDNS = Protocol{
		Code:       P_DNS,
		Size:       LengthPrefixedVarSize,
		Name:       "dns",
		VCode:      codeDNS,
		Transcoder: TranscoderDns,
	}
	protoDNS4 = Protocol{
		Code:       P_DNS4,
		Size:       LengthPrefixedVarSize,
		Name:       "dns4",
		VCode:      codeDNS4,
		Transcoder: TranscoderDns,
	}
	protoDNS6 = Protocol{
		Code:       P_DNS6,
		Size:       LengthPrefixedVarSize,
		Name:       "dns6",
		VCode:      codeDNS6,
		Transcoder: TranscoderDns,
	}
	protoDNSADDR = Protocol{
		Code:       P_DNSADDR,
		Size:       LengthPrefixedVarSize,
		Name:       "dnsaddr",
		VCode:      codeDNSADDR,
		Transcoder: TranscoderDns,
	}
	protoUDP = Protocol{
		Name:       "udp",
		Code:       P_UDP,
		VCode:      codeUDP,
		Size:       16,
		Path:       false,
		Transcoder: TranscoderPort,
	}
	protoDCCP = Protocol{
		Name:       "dccp",
		Code:       P_DCCP,
		VCode:      codeDCCP,
		Size:       16,
		Path:       false,
		Transcoder: TranscoderPort,
	}
	protoIP6 = Protocol{
		Name:       "ip6",
		Code:       P_IP6,
		VCode:      codeIP6,
		Size:       128,
		Transcoder: TranscoderIP6,
	}
	protoIPCIDR = Protocol{
		Name:       "ipcidr",
		Code:       P_IPCIDR,
		VCode:      codeIPCIDR,
		Size:       8,
		Transcoder: TranscoderIPCIDR,
	}
	// these require varint
	protoIP6ZONE = Protocol{
		Name:       "ip6zone",
		Code:       P_IP6ZONE,
		VCode:      codeIP6ZONE,
		Size:       LengthPrefixedVarSize,
		Path:       false,
		Transcoder: TranscoderIP6Zone,
	}
	protoSCTP = Protocol{
		Name:       "sctp",
		Code:       P_SCTP,
		VCode:      codeSCTP,
		Size:       16,
		Transcoder: TranscoderPort,
	}

	protoCIRCUIT = Protocol{
		Code:  P_CIRCUIT,
		Size:  0,
		Name:  "p2p-circuit",
		VCode: codeCIRCUIT,
	}

	protoONION2 = Protocol{
		Name:       "onion",
		Code:       P_ONION,
		VCode:      codeONION2,
		Size:       96,
		Transcoder: TranscoderOnion,
	}
	protoONION3 = Protocol{
		Name:       "onion3",
		Code:       P_ONION3,
		VCode:      codeONION3,
		Size:       296,
		Transcoder: TranscoderOnion3,
	}
	protoGARLIC64 = Protocol{
		Name:       "garlic64",
		Code:       P_GARLIC64,
		VCode:      codeGARLIC64,
		Size:       LengthPrefixedVarSize,
		Transcoder: TranscoderGarlic64,
	}
	protoGARLIC32 = Protocol{
		Name:       "garlic32",
		Code:       P_GARLIC32,
		VCode:      codeGARLIC32,
		Size:       LengthPrefixedVarSize,
		Transcoder: TranscoderGarlic32,
	}
	protoUTP = Protocol{
		Name:  "utp",
		Code:  P_UTP,
		VCode: codeUTP,
	}
	protoUDT = Protocol{
		Name:  "udt",
		Code:  P_UDT,
		VCode: codeUDT,
	}
	protoQUIC = Protocol{
		Name:  "quic",
		Code:  P_QUIC,
		VCode: codeQUIC,
	}
	protoQUICV1 = Protocol{
		Name:  "quic-v1",
		Code:  P_QUIC_V1,
		VCode: codeQUICV1,
	}
	protoWEBTRANSPORT = Protocol{
		Name:  "webtransport",
		Code:  P_WEBTRANSPORT,
		VCode: codeWEBTRANSPORT,
	}
	protoCERTHASH = Protocol{
		Name:       "certhash",
		Code:       P_CERTHASH,
		VCode:      codeCERTHASH,
		Size:       LengthPrefixedVarSize,
		Transcoder: TranscoderCertHash,
	}
	protoHTTP = Protocol{
		Name:  "http",
		Code:  P_HTTP,
		VCode: codeHTTP,
	}
	protoHTTPPath = Protocol{
		Name:       "http-path",
		Code:       P_HTTP_PATH,
		VCode:      codeHTTPPath,
		Size:       LengthPrefixedVarSize,
		Transcoder: TranscoderHTTPPath,
	}
	protoHTTPS = Protocol{
		Name:  "https",
		Code:  P_HTTPS,
		VCode: codeHTTPS,
	}
	protoP2P = Protocol{
		Name:       "p2p",
		Code:       P_P2P,
		VCode:      codeP2P,
		Size:       LengthPrefixedVarSize,
		Transcoder: TranscoderP2P,
	}
	protoUNIX = Protocol{
		Name:       "unix",
		Code:       P_UNIX,
		VCode:      codeUNIX,
		Size:       LengthPrefixedVarSize,
		Path:       true,
		Transcoder: TranscoderUnix,
	}
	protoP2P_WEBRTC_DIRECT = Protocol{
		Name:  "p2p-webrtc-direct",
		Code:  P_P2P_WEBRTC_DIRECT,
		VCode: codeP2P_WEBRTC_DIRECT,
	}
	protoTLS = Protocol{
		Name:  "tls",
		Code:  P_TLS,
		VCode: codeTLS,
	}
	protoSNI = Protocol{
		Name:       "sni",
		Size:       LengthPrefixedVarSize,
		Code:       P_SNI,
		VCode:      codeSNI,
		Transcoder: TranscoderDns,
	}
	protoNOISE = Protocol{
		Name:  "noise",
		Code:  P_NOISE,
		VCode: codeNOISE,
	}
	protoPlaintextV2 = Protocol{
		Name:  "plaintextv2",
		Code:  P_PLAINTEXTV2,
		VCode: codePlaintextV2,
	}
	protoWS = Protocol{
		Name:  "ws",
		Code:  P_WS,
		VCode: codeWS,
	}
	protoWSS = Protocol{
		Name:  "wss",
		Code:  P_WSS,
		VCode: codeWSS,
	}
	protoWebRTCDirect = Protocol{
		Name:  "webrtc-direct",
		Code:  P_WEBRTC_DIRECT,
		VCode: codeWebRTCDirect,
	}
	protoWebRTC = Protocol{
		Name:  "webrtc",
		Code:  P_WEBRTC,
		VCode: codeWebRTC,
	}
	protoMemory = Protocol{
		Name:       "memory",
		Code:       P_MEMORY,
		VCode:      codeMemory,
		Size:       64,
		Transcoder: TranscoderMemory,
	}
)

func init() {
	for _, p := range []Protocol{
		protoIP4,
		protoTCP,
		protoDNS,
		protoDNS4,
		protoDNS6,
		protoDNSADDR,
		protoUDP,
		protoDCCP,
		protoIP6,
		protoIP6ZONE,
		protoIPCIDR,
		protoSCTP,
		protoCIRCUIT,
		protoONION2,
		protoONION3,
		protoGARLIC64,
		protoGARLIC32,
		protoUTP,
		protoUDT,
		protoQUIC,
		protoQUICV1,
		protoWEBTRANSPORT,
		protoCERTHASH,
		protoHTTP,
		protoHTTPPath,
		protoHTTPS,
		protoP2P,
		protoUNIX,
		protoP2P_WEBRTC_DIRECT,
		protoTLS,
		protoSNI,
		protoNOISE,
		protoWS,
		protoWSS,
		protoPlaintextV2,
		protoWebRTCDirect,
		protoWebRTC,
		protoMemory,
	} {
		if err := AddProtocol(p); err != nil {
			panic(err)
		}
	}

	// explicitly set both of these
	protocolsByName["p2p"] = protoP2P
	protocolsByName["ipfs"] = protoP2P
}
