package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"source.quilibrium.com/quilibrium/monorepo/config"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

type PeerAuthenticator struct {
	logger *zap.Logger

	// config data is used to extract the peer priv key for credential creation
	config *config.P2PConfig

	// peer info manager is used to identify live peers
	peerInfoManager p2p.PeerInfoManager

	// prover registry and signer registry are used to confirm membership of
	// a given shard or global prover status
	proverRegistry consensus.ProverRegistry
	signerRegistry consensus.SignerRegistry

	// filter constrains the shard membership check to one specific filter
	filter []byte

	// self-explanatory
	whitelistedPeerIds map[string]struct{}
	selfPeerId         []byte

	// authentication scope is assigned to broadly services or specific methods:
	//   service: "package.Service"
	//   method:  "/package.Service/Method"
	servicePolicies map[string]channel.AllowedPeerPolicyType
	methodPolicies  map[string]channel.AllowedPeerPolicyType
}

func NewPeerAuthenticator(
	logger *zap.Logger,
	config *config.P2PConfig,
	peerInfoManager p2p.PeerInfoManager,
	proverRegistry consensus.ProverRegistry,
	signerRegistry consensus.SignerRegistry,
	filter []byte,
	whitelistedPeers [][]byte,
	servicePolicies map[string]channel.AllowedPeerPolicyType,
	methodPolicies map[string]channel.AllowedPeerPolicyType,
) *PeerAuthenticator {
	if servicePolicies == nil {
		servicePolicies = map[string]channel.AllowedPeerPolicyType{}
	}

	if methodPolicies == nil {
		methodPolicies = map[string]channel.AllowedPeerPolicyType{}
	}

	whitelistedPeerIds := make(map[string]struct{})
	for _, p := range whitelistedPeers {
		whitelistedPeerIds[string(p)] = struct{}{}
	}

	if config == nil {
		panic("no config")
	}

	privKey, err := hex.DecodeString(config.PeerPrivKey)
	if err != nil {
		panic(err)
	}

	pubKey, err := crypto.UnmarshalEd448PublicKey(privKey[57:])
	if err != nil {
		panic(err)
	}

	selfId, err := ppeer.IDFromPublicKey(pubKey)
	if err != nil {
		panic(err)
	}

	selfPeerId := []byte(selfId)

	return &PeerAuthenticator{
		logger,
		config,
		peerInfoManager,
		proverRegistry,
		signerRegistry,
		filter,
		whitelistedPeerIds,
		selfPeerId,
		servicePolicies,
		methodPolicies,
	}
}

// Identify identifies a peer from the grpc context data.
func (p *PeerAuthenticator) Identify(ctx context.Context) (ppeer.ID, error) {
	peerID, ok := qgrpc.PeerIDFromContext(ctx)
	if !ok {
		return "", errors.Wrap(errors.New("could not identify peer"), "identify")
	}

	return peerID, nil
}

// CreateTLSCredentials creates TLS credentials using the peer private key
// defined in the config, matching to the public key of the given peer –
// mismatches with expected peer key will produce a rejected certificate,
// preventing MITM attacks.
func (p *PeerAuthenticator) CreateServerTLSCredentials() (
	credentials.TransportCredentials,
	error,
) {
	cert, tc, err := p.createTLSCredentials()
	if err != nil {
		return tc, err
	}

	// Create TLS config with proper certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		ClientAuth:   tls.RequireAnyClientCert,
		// Custom verification to ensure peers use the same base key
		VerifyPeerCertificate: func(
			rawCerts [][]byte,
			verifiedChains [][]*x509.Certificate,
		) error {
			if len(rawCerts) == 0 {
				p.logger.Debug("no peer certificate provided")
				return errors.New("no peer certificate provided")
			}

			// Parse the peer certificate
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				p.logger.Debug("could not parse peer certificate")
				return errors.Wrap(err, "failed to parse peer certificate")
			}

			// For mutual authentication, verify the peer certificate was generated
			// from the same Ed448 seed by checking if the xsign matches
			peerEd25519PubKey, ok := peerCert.PublicKey.(ed25519.PublicKey)
			if !ok {
				p.logger.Debug("peer certificate has invalid key type")
				return errors.New("peer certificate does not use Ed25519 key")
			}

			if len(peerCert.DNSNames) != 1 {
				p.logger.Debug("dns mismatch")
				return errors.New("peer certificate dns mismatch")
			}

			xsign, err := hex.DecodeString(peerCert.DNSNames[0])
			if err != nil {
				p.logger.Debug("failed ot parse xsign")
				return errors.Wrap(err, "failed to parse xsign")
			}

			valid := ed448.Verify(
				ed448.PublicKey(xsign[:57]),
				slices.Concat([]byte("tls-cert-derivation"), peerEd25519PubKey),
				xsign[57:],
				"",
			)
			if !valid {
				p.logger.Debug("peer certificate invalid xsign")
				return errors.New("peer certificate invalid xsign")
			}

			pubkey, err := crypto.UnmarshalEd448PublicKey(xsign[:57])
			if err != nil {
				p.logger.Debug("could not obtain ed448 pubkey")
				return err
			}

			_, err = ppeer.IDFromPublicKey(pubkey)
			if err != nil {
				p.logger.Debug("could not derive peer id")
				return err
			}

			p.logger.Debug("certificate check succeeded")

			return nil
		},
		InsecureSkipVerify: true, // We handle verification in VerifyPeerCertificate
	}

	return credentials.NewTLS(tlsConfig), nil
}

func (p *PeerAuthenticator) CreateClientTLSCredentials(
	expectedPeerId []byte,
) (
	credentials.TransportCredentials,
	error,
) {
	cert, tc, err := p.createTLSCredentials()
	if err != nil {
		return tc, err
	}

	// Create TLS config with proper certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		ClientAuth:   tls.RequireAnyClientCert,
		// Custom verification to ensure peers use the same base key
		VerifyPeerCertificate: func(
			rawCerts [][]byte,
			verifiedChains [][]*x509.Certificate,
		) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate provided")
			}

			// Parse the peer certificate
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errors.Wrap(err, "failed to parse peer certificate")
			}

			// For mutual authentication, verify the peer certificate was generated
			// from the same Ed448 seed by checking if the xsign matches
			peerEd25519PubKey, ok := peerCert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("peer certificate does not use Ed25519 key")
			}

			if len(peerCert.DNSNames) != 1 {
				return errors.New("peer certificate dns mismatch")
			}

			xsign, err := hex.DecodeString(peerCert.DNSNames[0])
			if err != nil {
				return errors.Wrap(err, "failed to parse xsign")
			}

			valid := ed448.Verify(
				ed448.PublicKey(xsign[:57]),
				slices.Concat([]byte("tls-cert-derivation"), peerEd25519PubKey),
				xsign[57:],
				"",
			)
			if !valid {
				return errors.New("peer certificate invalid xsign")
			}

			pubkey, err := crypto.UnmarshalEd448PublicKey(xsign[:57])
			if err != nil {
				return err
			}

			peerId, err := ppeer.IDFromPublicKey(pubkey)
			if err != nil {
				return err
			}

			if !bytes.Equal([]byte(peerId), expectedPeerId) {
				return errors.New("peer mismatch")
			}

			return nil
		},
		InsecureSkipVerify: true, // We handle verification in VerifyPeerCertificate
	}

	return credentials.NewTLS(tlsConfig), nil
}

func (p *PeerAuthenticator) createTLSCredentials() (
	tls.Certificate,
	credentials.TransportCredentials,
	error,
) {
	if p.config.PeerPrivKey == "" {
		return tls.Certificate{}, nil, errors.Wrap(
			errors.New("peer private key is required for TLS"),
			"create tls credentials",
		)
	}

	// Decode the peer private key
	peerPrivKeyBytes, err := hex.DecodeString(p.config.PeerPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	// Unmarshal the Ed448 private key
	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKeyBytes)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	// Extract the raw Ed448 key material
	privKeyRaw, err := privKey.Raw()
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	// Create Ed448 key pair from the raw key material
	if len(privKeyRaw) != ed448.PrivateKeySize {
		return tls.Certificate{}, nil, errors.Wrap(
			errors.New("invalid ed448 private key size"),
			"create tls credentials",
		)
	}

	// Since Go's x509 doesn't support Ed448, we'll derive an Ed25519 key for TLS
	// from the Ed448 key material to maintain deterministic behavior

	// Create deterministic Ed25519 key from Ed448 seed
	hasher := sha256.New()
	hasher.Write(privKeyRaw[:ed448.SeedSize])
	hasher.Write([]byte("tls-cert-derivation")) // Add context to avoid key reuse
	ed25519Seed := hasher.Sum(nil)[:ed25519.SeedSize]

	// Generate Ed25519 key pair for TLS certificate
	ed25519PrivKey := ed25519.NewKeyFromSeed(ed25519Seed)
	ed25519PubKey := ed25519PrivKey.Public().(ed25519.PublicKey)

	// Create a self-signed certificate using the Ed25519 key (for TLS
	// compatibility)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"QTLS"},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	rawPub, err := privKey.GetPublic().Raw()
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	// Construct cross-signature of derived ed25519 key from ed448 key
	xsign, err := privKey.Sign(
		slices.Concat([]byte("tls-cert-derivation"), ed25519PubKey),
	)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	template.IPAddresses = []net.IP{}
	template.DNSNames = []string{hex.EncodeToString(
		slices.Concat(rawPub, xsign),
	)}

	// Create certificate with Ed25519 key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		ed25519PubKey,
		ed25519PrivKey,
	)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrap(err, "create tls credentials")
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  ed25519PrivKey,
	}
	return cert, nil, nil
}

func (p *PeerAuthenticator) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	ctx, err := p.authorize(ctx, info.FullMethod)
	if err != nil {
		return ctx, err
	}

	return handler(ctx, req)
}

func (p *PeerAuthenticator) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	ctx, err := p.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}

	ss = &authenticatedStream{ServerStream: ss, ctx: ctx}
	return handler(srv, ss)
}

func (p *PeerAuthenticator) extractPeer(ctx context.Context) (
	[]byte,
	[]byte,
	error,
) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, nil, errors.New("no peer")
	}

	ti, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 ||
		len(ti.State.PeerCertificates[0].DNSNames) == 0 {
		return nil, nil, errors.New("no peer cert")
	}

	xsign, err := hex.DecodeString(ti.State.PeerCertificates[0].DNSNames[0])
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse xsign")
	}

	pubkey, err := crypto.UnmarshalEd448PublicKey(xsign[:57])
	if err != nil {
		return nil, nil, err
	}

	peerId, err := ppeer.IDFromPublicKey(pubkey)
	if err != nil {
		return nil, nil, err
	}

	return xsign[:57], []byte(peerId), nil
}

func (p *PeerAuthenticator) authorize(
	ctx context.Context,
	fullMethod string,
) (context.Context, error) {
	_, id, err := p.extractPeer(ctx)
	if err != nil {
		return ctx, status.Errorf(
			codes.Unauthenticated,
			"mtls peer missing: %v",
			err,
		)
	}

	pol := p.policyFor(fullMethod)
	switch pol {
	case channel.AnyPeer:
		return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
	case channel.OnlySelfPeer:
		if p.isSelf(id) {
			return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
		}
	case channel.AnyProverPeer:
		if p.isAnyProver(id) {
			return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
		}
	case channel.OnlyGlobalProverPeer:
		if p.isGlobalProver(id) {
			return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
		}
	case channel.OnlyShardProverPeer:
		if p.isShardProver(id) {
			return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
		}
	case channel.OnlyWhitelistedPeers:
		if _, ok := p.whitelistedPeerIds[string(id)]; ok {
			return qgrpc.NewContextWithPeerID(ctx, ppeer.ID(id)), nil
		}
	}

	return ctx, status.Errorf(
		codes.PermissionDenied,
		"peer not allowed by policy %v",
		pol,
	)
}

func (p *PeerAuthenticator) isSelf(id []byte) bool {
	if !bytes.Equal(id, p.selfPeerId) {
		p.logger.Error(
			"request authentication for self failed",
			zap.Error(errors.New("peer certificate public key mismatch")),
		)
		return false
	}

	return true
}

func (p *PeerAuthenticator) isAnyProver(id []byte) bool {
	if p.proverRegistry == nil {
		p.logger.Error(
			"request authentication for any prover failed",
			zap.Error(errors.New("prover registry not set")),
		)
		return false
	}

	if p.signerRegistry == nil {
		p.logger.Error(
			"request authentication for any prover failed",
			zap.Error(errors.New("signer registry not set")),
		)
		return false
	}

	signer, err := p.signerRegistry.GetKeyRegistry(id)
	if err != nil || signer == nil || signer.ProverKey == nil ||
		signer.ProverKey.KeyValue == nil {
		p.logger.Error(
			"request authentication for any prover failed",
			zap.Error(errors.New("peer key registry could not be resolved")),
		)
		return false
	}

	proverAddr, err := poseidon.HashBytes(signer.ProverKey.KeyValue)
	if err != nil {
		p.logger.Error("could not derive prover address", zap.Error(err))
		return false
	}

	info, err := p.proverRegistry.GetProverInfo(
		proverAddr.FillBytes(make([]byte, 32)),
	)
	if err != nil || info == nil {
		p.logger.Error(
			"request authentication for any prover failed",
			zap.Error(errors.New("prover info could not be found")),
		)
		return false
	}

	return true
}

func (p *PeerAuthenticator) isGlobalProver(id []byte) bool {
	if p.proverRegistry == nil {
		p.logger.Error(
			"request authenticated for global prover failed",
			zap.Error(errors.New("prover registry not set")),
		)
		return false
	}

	if p.signerRegistry == nil {
		p.logger.Error(
			"request authenticated for global prover failed",
			zap.Error(errors.New("signer registry not set")),
		)
		return false
	}

	signer, err := p.signerRegistry.GetKeyRegistry(id)
	if err != nil || signer == nil || signer.ProverKey == nil ||
		signer.ProverKey.KeyValue == nil {
		p.logger.Error(
			"request authenticated for global prover failed",
			zap.Error(errors.New("peer key registry could not be resolved")),
		)
		return false
	}

	proverAddr, err := poseidon.HashBytes(signer.ProverKey.KeyValue)
	if err != nil {
		p.logger.Error(
			"request authenticated for global prover failed",
			zap.Error(err),
		)
		return false
	}

	info, err := p.proverRegistry.GetProverInfo(
		proverAddr.FillBytes(make([]byte, 32)),
	)
	if err != nil || info == nil {
		p.logger.Error(
			"request authenticated for global prover failed",
			zap.Error(errors.New("prover info could not be found")),
		)
		return false
	}

	for _, alloc := range info.Allocations {
		if len(alloc.ConfirmationFilter) == 0 {
			return true
		}
	}

	p.logger.Error(
		"request authenticated for global prover failed",
		zap.Error(errors.New("not global prover")),
	)
	return false
}

func (p *PeerAuthenticator) isShardProver(id []byte) bool {
	if p.proverRegistry == nil {
		p.logger.Error(
			"request authentication for shard prover failed",
			zap.Error(errors.New("prover registry not set")),
		)
		return false
	}

	if p.signerRegistry == nil {
		p.logger.Error(
			"request authentication for shard prover failed",
			zap.Error(errors.New("signer registry not set")),
		)
		return false
	}

	signer, err := p.signerRegistry.GetKeyRegistry(id)
	if err != nil || signer == nil || signer.ProverKey == nil ||
		signer.ProverKey.KeyValue == nil {
		p.logger.Error(
			"request authentication for shard prover failed",
			zap.Error(errors.New("peer key registry could not be resolved")),
		)
		return false
	}

	proverAddr, err := poseidon.HashBytes(signer.ProverKey.KeyValue)
	if err != nil {
		p.logger.Error(
			"request authentication for shard prover failed",
			zap.Error(err),
		)
		return false
	}

	info, err := p.proverRegistry.GetProverInfo(
		proverAddr.FillBytes(make([]byte, 32)),
	)
	if err != nil || info == nil {
		p.logger.Error(
			"request authentication for shard prover failed",
			zap.Error(errors.New("prover info could not be found")),
		)
		return false
	}

	for _, alloc := range info.Allocations {
		if bytes.Equal(alloc.ConfirmationFilter, p.filter) {
			return true
		}
	}

	p.logger.Error(
		"request authentication for shard prover failed",
		zap.Error(errors.New("not shard prover")),
	)
	return false
}

func (p *PeerAuthenticator) policyFor(
	fullMethod string,
) channel.AllowedPeerPolicyType {
	// fullMethod = "/package.Service/Method"
	if p, ok := p.methodPolicies[fullMethod]; ok {
		return p
	}

	// Extract "package.Service"
	svc := strings.TrimPrefix(fullMethod, "/")
	if i := strings.IndexByte(svc, '/'); i >= 0 {
		svc = svc[:i]
	}
	if p, ok := p.servicePolicies[svc]; ok {
		return p
	}

	// Use the strictest policy for fallthrough cases – hitting this is an
	// implementation bug, all scopes should be defined
	p.logger.Error(
		"undefined scope requested",
		zap.String("scope", fullMethod),
	)
	return channel.OnlySelfPeer
}

type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *authenticatedStream) Context() context.Context { return w.ctx }

var _ channel.AuthenticationProvider = (*PeerAuthenticator)(nil)
