package protobufs

// Canonical type constants for all protobuf messages
// These are used as prefixes in ToCanonicalBytes() serialization
const (
	// Core node types (0x0100 - 0x01FF)
	MessageType                                uint32 = 0x0100
	PeerInfoType                               uint32 = 0x0101
	CapabilityType                             uint32 = 0x0102
	Ed448PublicKeyType                         uint32 = 0x0110
	Ed448PrivateKeyType                        uint32 = 0x0111
	Ed448SignatureType                         uint32 = 0x0112
	X448PublicKeyType                          uint32 = 0x0113
	X448PrivateKeyType                         uint32 = 0x0114
	PCASPublicKeyType                          uint32 = 0x0115 // reserved
	PCASPrivateKeyType                         uint32 = 0x0116 // reserved
	BLS48581G2PublicKeyType                    uint32 = 0x0117
	BLS48581G2PrivateKeyType                   uint32 = 0x0118
	BLS48581SignatureType                      uint32 = 0x0119
	BLS48581SignatureWithProofOfPossessionType uint32 = 0x011A
	BLS48581AddressedSignatureType             uint32 = 0x011B
	BLS48581AggregateSignatureType             uint32 = 0x011C
	Decaf448PublicKeyType                      uint32 = 0x011D
	Decaf448PrivateKeyType                     uint32 = 0x011E
	Decaf448SignatureType                      uint32 = 0x011F
	SignedX448KeyType                          uint32 = 0x0120
	SignedDevicePreKeyType                     uint32 = 0x0121
	KeyCollectionType                          uint32 = 0x0122
	KeyRegistryType                            uint32 = 0x0123

	// Channel types (0x0200 - 0x02FF)
	P2PChannelEnvelopeType uint32 = 0x0200
	MessageCiphertextType  uint32 = 0x0201
	InboxMessageType       uint32 = 0x0202
	HubAddInboxType        uint32 = 0x0203
	HubDeleteInboxType     uint32 = 0x0204

	// Global types (0x0300 - 0x03FF)
	LegacyProverRequestType uint32 = 0x0300
	ProverJoinType          uint32 = 0x0301
	ProverLeaveType         uint32 = 0x0302
	ProverPauseType         uint32 = 0x0303
	ProverResumeType        uint32 = 0x0304
	ProverConfirmType       uint32 = 0x0305
	ProverRejectType        uint32 = 0x0306
	ProverKickType          uint32 = 0x0307
	ProverUpdateType        uint32 = 0x0308
	GlobalFrameHeaderType   uint32 = 0x0309
	FrameHeaderType         uint32 = 0x030A
	ProverLivenessCheckType uint32 = 0x030B
	FrameVoteType           uint32 = 0x030C
	FrameConfirmationType   uint32 = 0x030D
	GlobalFrameType         uint32 = 0x030E
	AppShardFrameType       uint32 = 0x030F
	SeniorityMergeType      uint32 = 0x0310
	MessageRequestType      uint32 = 0x0311
	MessageBundleType       uint32 = 0x0312
	MultiproofType          uint32 = 0x0313
	PathType                uint32 = 0x0314
	TraversalSubProofType   uint32 = 0x0315
	TraversalProofType      uint32 = 0x0316

	// Hypergraph types (0x0400 - 0x04FF)
	HypergraphConfigurationType uint32 = 0x0401
	HypergraphDeploymentType    uint32 = 0x0402
	HypergraphUpdateType        uint32 = 0x0403
	VertexAddType               uint32 = 0x0404
	VertexRemoveType            uint32 = 0x0405
	HyperedgeAddType            uint32 = 0x0406
	HyperedgeRemoveType         uint32 = 0x0407

	// Token types (0x0500 - 0x05FF)
	AuthorityType                uint32 = 0x0500
	FeeBasisStructType           uint32 = 0x0501
	TokenMintStrategyType        uint32 = 0x0502
	TokenConfigurationType       uint32 = 0x0503
	TokenDeploymentType          uint32 = 0x0504
	TokenUpdateType              uint32 = 0x0505
	RecipientBundleType          uint32 = 0x0506
	TransactionInputType         uint32 = 0x0507
	TransactionOutputType        uint32 = 0x0508
	TransactionType              uint32 = 0x0509
	PendingTransactionInputType  uint32 = 0x050A
	PendingTransactionOutputType uint32 = 0x050B
	PendingTransactionType       uint32 = 0x050C
	MintTransactionInputType     uint32 = 0x050D
	MintTransactionOutputType    uint32 = 0x050E
	MintTransactionType          uint32 = 0x050F

	// Compute types (0x0600 - 0x06FF)
	ComputeConfigurationType     uint32 = 0x0600
	ComputeDeploymentType        uint32 = 0x0601
	ComputeUpdateType            uint32 = 0x0602
	CodeDeploymentType           uint32 = 0x0603
	ApplicationType              uint32 = 0x0604
	IntrinsicExecutionInputType  uint32 = 0x0605
	IntrinsicExecutionOutputType uint32 = 0x0606
	ExecutionDependencyType      uint32 = 0x0607
	ExecuteOperationType         uint32 = 0x0608
	ExecutionNodeType            uint32 = 0x0609
	ExecutionDAGType             uint32 = 0x060A
	ExecutionStageType           uint32 = 0x060B
	CodeExecuteType              uint32 = 0x060C
	StateTransitionType          uint32 = 0x060D
	ExecutionResultType          uint32 = 0x060E
	CodeFinalizeType             uint32 = 0x060F

	// Emergency types
	GlobalAlertType uint32 = 0x0911
)
