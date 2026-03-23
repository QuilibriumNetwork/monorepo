package token

import (
	"context"
	stdcrypto "crypto"
	"fmt"
	"io"
	"math/big"

	"google.golang.org/grpc"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// ---------------------------------------------------------------------------
// mockNodeServiceClient
// ---------------------------------------------------------------------------

type mockNodeServiceClient struct {
	// Captured values from Send()
	lastSendRequest *protobufs.SendRequest

	// Configurable return values
	sendErr            error
	nodeInfoResponse   *protobufs.NodeInfoResponse
	nodeInfoErr        error
	tokensByAcctResp   *protobufs.GetTokensByAccountResponse
	tokensByAcctErr    error
}

func (m *mockNodeServiceClient) Send(
	ctx context.Context,
	in *protobufs.SendRequest,
	opts ...grpc.CallOption,
) (*protobufs.SendResponse, error) {
	m.lastSendRequest = in
	if m.sendErr != nil {
		return nil, m.sendErr
	}
	return &protobufs.SendResponse{}, nil
}

func (m *mockNodeServiceClient) GetNodeInfo(
	ctx context.Context,
	in *protobufs.GetNodeInfoRequest,
	opts ...grpc.CallOption,
) (*protobufs.NodeInfoResponse, error) {
	if m.nodeInfoErr != nil {
		return nil, m.nodeInfoErr
	}
	if m.nodeInfoResponse != nil {
		return m.nodeInfoResponse, nil
	}
	return &protobufs.NodeInfoResponse{LastGlobalHeadFrame: 100}, nil
}

func (m *mockNodeServiceClient) GetTokensByAccount(
	ctx context.Context,
	in *protobufs.GetTokensByAccountRequest,
	opts ...grpc.CallOption,
) (*protobufs.GetTokensByAccountResponse, error) {
	if m.tokensByAcctErr != nil {
		return nil, m.tokensByAcctErr
	}
	if m.tokensByAcctResp != nil {
		return m.tokensByAcctResp, nil
	}
	return &protobufs.GetTokensByAccountResponse{}, nil
}

func (m *mockNodeServiceClient) GetPeerInfo(
	ctx context.Context,
	in *protobufs.GetPeerInfoRequest,
	opts ...grpc.CallOption,
) (*protobufs.PeerInfoResponse, error) {
	return &protobufs.PeerInfoResponse{}, nil
}

func (m *mockNodeServiceClient) GetWorkerInfo(
	ctx context.Context,
	in *protobufs.GetWorkerInfoRequest,
	opts ...grpc.CallOption,
) (*protobufs.WorkerInfoResponse, error) {
	return &protobufs.WorkerInfoResponse{}, nil
}

func (m *mockNodeServiceClient) GetMetrics(
	ctx context.Context,
	in *protobufs.GetMetricsRequest,
	opts ...grpc.CallOption,
) (*protobufs.GetMetricsResponse, error) {
	return &protobufs.GetMetricsResponse{}, nil
}

func (m *mockNodeServiceClient) GetVertexData(
	ctx context.Context,
	in *protobufs.GetVertexDataRequest,
	opts ...grpc.CallOption,
) (*protobufs.GetVertexDataResponse, error) {
	return &protobufs.GetVertexDataResponse{}, nil
}

func (m *mockNodeServiceClient) GetHyperedgeData(
	ctx context.Context,
	in *protobufs.GetHyperedgeDataRequest,
	opts ...grpc.CallOption,
) (*protobufs.GetHyperedgeDataResponse, error) {
	return &protobufs.GetHyperedgeDataResponse{}, nil
}

func (m *mockNodeServiceClient) CreateTraversalProof(
	ctx context.Context,
	in *protobufs.CreateTraversalProofRequest,
	opts ...grpc.CallOption,
) (*protobufs.CreateTraversalProofResponse, error) {
	return &protobufs.CreateTraversalProofResponse{}, nil
}

func (m *mockNodeServiceClient) GetShardInfo(
	ctx context.Context,
	in *protobufs.GetShardInfoRequest,
	opts ...grpc.CallOption,
) (*protobufs.GetShardInfoResponse, error) {
	return &protobufs.GetShardInfoResponse{}, nil
}

func (m *mockNodeServiceClient) RequestJoin(
	ctx context.Context,
	in *protobufs.RequestJoinRequest,
	opts ...grpc.CallOption,
) (*protobufs.RequestJoinResponse, error) {
	return &protobufs.RequestJoinResponse{}, nil
}

func (m *mockNodeServiceClient) SetManuallyManaged(
	ctx context.Context,
	in *protobufs.SetManuallyManagedRequest,
	opts ...grpc.CallOption,
) (*protobufs.SetManuallyManagedResponse, error) {
	return &protobufs.SetManuallyManagedResponse{}, nil
}

func (m *mockNodeServiceClient) GetLatestFrame(
	ctx context.Context,
	in *protobufs.GetGlobalFrameRequest,
	opts ...grpc.CallOption,
) (*protobufs.GlobalFrameResponse, error) {
	return &protobufs.GlobalFrameResponse{}, nil
}

func (m *mockNodeServiceClient) SubmitMessage(
	ctx context.Context,
	in *protobufs.SubmitMessageRequest,
	opts ...grpc.CallOption,
) (*protobufs.SubmitMessageResponse, error) {
	return &protobufs.SubmitMessageResponse{}, nil
}

// ---------------------------------------------------------------------------
// mockSigner
// ---------------------------------------------------------------------------

type mockSigner struct {
	// Captured call args
	lastMessage []byte
	lastDomain  []byte

	// Configurable return values
	signErr error
	sigData []byte
}

func (m *mockSigner) Public() stdcrypto.PublicKey {
	return []byte("mock-public-key")
}

func (m *mockSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts stdcrypto.SignerOpts,
) ([]byte, error) {
	return m.sigData, m.signErr
}

func (m *mockSigner) GetType() crypto.KeyType {
	return crypto.KeyTypeBLS48581G1
}

func (m *mockSigner) Private() []byte {
	return []byte("mock-private-key")
}

func (m *mockSigner) SignWithDomain(
	message []byte,
	domain []byte,
) ([]byte, error) {
	m.lastMessage = message
	m.lastDomain = domain
	if m.signErr != nil {
		return nil, m.signErr
	}
	if m.sigData != nil {
		return m.sigData, nil
	}
	return []byte("mock-signature-data"), nil
}

// ---------------------------------------------------------------------------
// mockAgreement
// ---------------------------------------------------------------------------

type mockAgreement struct {
	publicKey  []byte
	privateKey []byte
}

func newMockAgreement(pub, priv []byte) *mockAgreement {
	return &mockAgreement{publicKey: pub, privateKey: priv}
}

func (m *mockAgreement) Public() []byte {
	return m.publicKey
}

func (m *mockAgreement) Private() []byte {
	return m.privateKey
}

func (m *mockAgreement) AgreeWith(publicKey []byte) ([]byte, error) {
	return []byte("mock-shared-secret"), nil
}

// ---------------------------------------------------------------------------
// mockKeyManager
// ---------------------------------------------------------------------------

type mockKeyManager struct {
	signer       *mockSigner
	signerErr    error
	agreements   map[string]*mockAgreement
	agreementErr error
}

func newMockKeyManager() *mockKeyManager {
	return &mockKeyManager{
		signer: &mockSigner{
			sigData: []byte("mock-signature-data"),
		},
		agreements: map[string]*mockAgreement{
			"q-view-key":  newMockAgreement(make([]byte, 56), make([]byte, 56)),
			"q-spend-key": newMockAgreement(make([]byte, 56), make([]byte, 56)),
		},
	}
}

func (m *mockKeyManager) GetRawKey(id string) (*keys.Key, error) {
	return &keys.Key{Id: id}, nil
}

func (m *mockKeyManager) GetSigningKey(id string) (crypto.Signer, error) {
	if m.signerErr != nil {
		return nil, m.signerErr
	}
	return m.signer, nil
}

func (m *mockKeyManager) GetAgreementKey(id string) (crypto.Agreement, error) {
	if m.agreementErr != nil {
		return nil, m.agreementErr
	}
	if ag, ok := m.agreements[id]; ok {
		return ag, nil
	}
	return nil, fmt.Errorf("agreement key %q not found", id)
}

func (m *mockKeyManager) PutRawKey(key *keys.Key) error {
	return nil
}

func (m *mockKeyManager) CreateSigningKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Signer, []byte, error) {
	return m.signer, []byte("mock-popk"), nil
}

func (m *mockKeyManager) CreateAgreementKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Agreement, error) {
	ag := newMockAgreement(make([]byte, 56), make([]byte, 56))
	m.agreements[id] = ag
	return ag, nil
}

func (m *mockKeyManager) DeleteKey(id string) error {
	return nil
}

func (m *mockKeyManager) ListKeys() ([]*keys.Key, error) {
	return nil, nil
}

func (m *mockKeyManager) ValidateSignature(
	keyType crypto.KeyType,
	publicKey []byte,
	message []byte,
	signature []byte,
	domain []byte,
) (bool, error) {
	return true, nil
}

func (m *mockKeyManager) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (crypto.BlsAggregateOutput, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// mockBulletproofProver
// ---------------------------------------------------------------------------

type mockBulletproofProver struct{}

func (m *mockBulletproofProver) GenerateRangeProof(
	values []uint64,
	blinding []byte,
	bitSize uint64,
) (crypto.RangeProofResult, error) {
	return crypto.RangeProofResult{}, nil
}

func (m *mockBulletproofProver) GenerateInputCommitmentsFromBig(
	values []*big.Int,
	blinding []byte,
) []byte {
	return nil
}

func (m *mockBulletproofProver) GenerateRangeProofFromBig(
	values []*big.Int,
	blinding []byte,
	bitSize uint64,
) (crypto.RangeProofResult, error) {
	return crypto.RangeProofResult{}, nil
}

func (m *mockBulletproofProver) VerifyRangeProof(
	proof []byte,
	commitment []byte,
	bitSize uint64,
) bool {
	return true
}

func (m *mockBulletproofProver) SumCheck(
	inputs [][]byte,
	additionalInputs []*big.Int,
	outputs [][]byte,
	additionalOutputs []*big.Int,
) bool {
	return true
}

func (m *mockBulletproofProver) SignHidden(
	sharedSecret []byte,
	spendKey []byte,
	extTranscript []byte,
	amount []byte,
	blind []byte,
) []byte {
	return nil
}

func (m *mockBulletproofProver) VerifyHidden(
	challenge []byte,
	extTranscript []byte,
	s1, s2, s3 []byte,
	point []byte,
	commitment []byte,
) bool {
	return true
}

func (m *mockBulletproofProver) SimpleSign(
	secretKey []byte,
	message []byte,
) []byte {
	return nil
}

func (m *mockBulletproofProver) SimpleVerify(
	message []byte,
	signature []byte,
	point []byte,
) bool {
	return true
}

// ---------------------------------------------------------------------------
// mockInclusionProver
// ---------------------------------------------------------------------------

type mockInclusionProver struct{}

func (m *mockInclusionProver) CommitRaw(
	data []byte,
	polySize uint64,
) ([]byte, error) {
	return []byte("mock-commitment"), nil
}

func (m *mockInclusionProver) ProveRaw(
	data []byte,
	index int,
	polySize uint64,
) ([]byte, error) {
	return []byte("mock-proof"), nil
}

func (m *mockInclusionProver) VerifyRaw(
	data []byte,
	commit []byte,
	index uint64,
	proof []byte,
	polySize uint64,
) (bool, error) {
	return true, nil
}

func (m *mockInclusionProver) ProveMultiple(
	commitments [][]byte,
	polys [][]byte,
	indices []uint64,
	polySize uint64,
) crypto.Multiproof {
	return &mockMultiproof{}
}

func (m *mockInclusionProver) VerifyMultiple(
	commitments [][]byte,
	evaluations [][]byte,
	indices []uint64,
	polySize uint64,
	multiCommitment []byte,
	proof []byte,
) bool {
	return true
}

func (m *mockInclusionProver) NewMultiproof() crypto.Multiproof {
	return &mockMultiproof{}
}

// ---------------------------------------------------------------------------
// mockMultiproof
// ---------------------------------------------------------------------------

type mockMultiproof struct{}

func (m *mockMultiproof) GetMulticommitment() []byte { return nil }
func (m *mockMultiproof) GetProof() []byte           { return nil }
func (m *mockMultiproof) ToBytes() ([]byte, error)   { return nil, nil }
func (m *mockMultiproof) FromBytes([]byte) error     { return nil }

// ---------------------------------------------------------------------------
// mockVerifiableEncryptor
// ---------------------------------------------------------------------------

type mockVerifiableEncryptor struct{}

func (m *mockVerifiableEncryptor) Encrypt(
	data []byte,
	publicKey []byte,
) []crypto.VerEncProof {
	return nil
}

func (m *mockVerifiableEncryptor) Decrypt(
	encrypted []crypto.VerEnc,
	decryptionKey []byte,
) []byte {
	return nil
}

func (m *mockVerifiableEncryptor) EncryptAndCompress(
	data []byte,
	publicKey []byte,
) []crypto.VerEnc {
	return nil
}

func (m *mockVerifiableEncryptor) ProofFromBytes(data []byte) crypto.VerEncProof {
	return nil
}

func (m *mockVerifiableEncryptor) FromBytes(data []byte) crypto.VerEnc {
	return nil
}

// ---------------------------------------------------------------------------
// mockDecafConstructor
// ---------------------------------------------------------------------------

type mockDecafConstructor struct{}

func (m *mockDecafConstructor) New() (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafConstructor) FromBytes(
	privateKey []byte,
	publicKey []byte,
) (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafConstructor) HashToScalar(
	input []byte,
) (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafConstructor) NewFromScalar(
	input []byte,
) (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafConstructor) AltGenerator() []byte {
	return make([]byte, 56)
}

// ---------------------------------------------------------------------------
// mockDecafAgreement
// ---------------------------------------------------------------------------

type mockDecafAgreement struct{}

func (m *mockDecafAgreement) Private() []byte {
	return make([]byte, 56)
}

func (m *mockDecafAgreement) Public() []byte {
	return make([]byte, 56)
}

func (m *mockDecafAgreement) AgreeWith(publicKey []byte) ([]byte, error) {
	return make([]byte, 56), nil
}

func (m *mockDecafAgreement) AgreeWithAndHashToScalar(
	publicKey []byte,
) (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafAgreement) InverseScalar() (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafAgreement) ScalarMult(scalar []byte) (crypto.DecafAgreement, error) {
	return &mockDecafAgreement{}, nil
}

func (m *mockDecafAgreement) Add(publicKey []byte) ([]byte, error) {
	return make([]byte, 56), nil
}
