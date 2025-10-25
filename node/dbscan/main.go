package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"sort"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var (
	configDirectory1 = flag.String(
		"config1",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
	configDirectory2 = flag.String(
		"config2",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)

	// *char flags
	blockchar         = "█"
	bver              = "Bloom"
	char      *string = &blockchar
	ver       *string = &bver
)

func main() {
	config.Flags(&char, &ver)
	flag.Parse()

	nodeConfig1, err := config.LoadConfig(*configDirectory1, "", false)
	if err != nil {
		log.Fatal("failed to load config", err)
	}

	logger, closer, err := nodeConfig1.CreateLogger(0, true)
	if err != nil {
		log.Fatal("failed to create logger", err)
	}
	defer closer.Close()

	db1 := store.NewPebbleDB(logger, nodeConfig1.DB, uint(0))
	defer db1.Close()

	iter1, err := db1.NewIter([]byte{0x00}, []byte{0xff})
	if err != nil {
		logger.Error("failed to create iterator", zap.Error(err))
	}
	defer iter1.Close()

	nodeConfig2, err := config.LoadConfig(*configDirectory2, "", false)
	if err != nil {
		log.Fatal("failed to load config", err)
	}

	db2 := store.NewPebbleDB(logger, nodeConfig2.DB, uint(0))
	defer db2.Close()

	iter2, err := db2.NewIter([]byte{0x00}, []byte{0xff})
	if err != nil {
		logger.Error("failed to create iterator", zap.Error(err))
	}
	defer iter2.Close()

	iter1Valid := iter1.First()
	iter2Valid := iter2.First()

	onlyDB1 := 0
	onlyDB2 := 0
	valueDiff := 0
	keyPresenceMap := make(map[string]*keyPresence)

	for iter1Valid || iter2Valid {
		var key1, key2 []byte
		var value1, value2 []byte
		var decoded1, decoded2 string

		if iter1Valid {
			key1 = iter1.Key()
			value1 = iter1.Value()
			decoded1 = decodeValue(key1, value1)
			recordKeyPresence(keyPresenceMap, key1, true)
		}
		if iter2Valid {
			key2 = iter2.Key()
			value2 = iter2.Value()
			decoded2 = decodeValue(key2, value2)
			recordKeyPresence(keyPresenceMap, key2, false)
		}

		switch {
		case iter1Valid && iter2Valid:
			comparison := bytes.Compare(key1, key2)
			if comparison == 0 {
				if bytes.Equal(value1, value2) {
					fmt.Printf(
						"key: %s\nsemantic: %s\nvalues identical in %s and %s\nvalue:\n%s\n\n",
						shortHex(key1),
						describeKey(key1),
						*configDirectory1,
						*configDirectory2,
						indent(decoded1),
					)
				} else {
					valueDiff++
					fmt.Printf(
						"key: %s\nsemantic: %s\nvalue (%s):\n%s\nvalue (%s):\n%s\n",
						shortHex(key1),
						describeKey(key1),
						*configDirectory1,
						indent(decoded1),
						*configDirectory2,
						indent(decoded2),
					)
					if diff := diffStrings(decoded1, decoded2); diff != "" {
						fmt.Printf("diff:\n%s\n", indent(diff))
					}
					fmt.Printf("\n")
				}
				iter1Valid = iter1.Next()
				iter2Valid = iter2.Next()
			} else if comparison < 0 {
				onlyDB1++
				fmt.Printf(
					"key only in %s: %s\nsemantic: %s\nvalue:\n%s\n\n",
					*configDirectory1,
					shortHex(key1),
					describeKey(key1),
					indent(decoded1),
				)
				iter1Valid = iter1.Next()
			} else {
				onlyDB2++
				fmt.Printf(
					"key only in %s: %s\nsemantic: %s\nvalue:\n%s\n\n",
					*configDirectory2,
					shortHex(key2),
					describeKey(key2),
					indent(decoded2),
				)
				iter2Valid = iter2.Next()
			}
		case iter1Valid:
			onlyDB1++
			fmt.Printf(
				"key only in %s: %s\nsemantic: %s\nvalue:\n%s\n\n",
				*configDirectory1,
				shortHex(key1),
				describeKey(key1),
				indent(decoded1),
			)
			iter1Valid = iter1.Next()
		case iter2Valid:
			onlyDB2++
			fmt.Printf(
				"key only in %s: %s\nsemantic: %s\nvalue:\n%s\n\n",
				*configDirectory2,
				shortHex(key2),
				describeKey(key2),
				indent(decoded2),
			)
			iter2Valid = iter2.Next()
		}
	}

	fmt.Printf(
		"summary: %d keys only in %s, %d keys only in %s, %d keys with differing values\n",
		onlyDB1,
		*configDirectory1,
		onlyDB2,
		*configDirectory2,
		valueDiff,
	)

	if len(keyPresenceMap) > 0 {
		allKeys := make([]string, 0, len(keyPresenceMap))
		for key := range keyPresenceMap {
			allKeys = append(allKeys, key)
		}
		sort.Strings(allKeys)

		fmt.Println("key presence by database:")
		for _, key := range allKeys {
			entry := keyPresenceMap[key]
			var status string
			switch {
			case entry.inFirst && entry.inSecond:
				status = fmt.Sprintf("present in %s and %s", *configDirectory1, *configDirectory2)
			case entry.inFirst:
				status = fmt.Sprintf("only present in %s", *configDirectory1)
			case entry.inSecond:
				status = fmt.Sprintf("only present in %s", *configDirectory2)
			default:
				status = "not present in either configuration"
			}
			fmt.Printf("  %s -> %s\n", key, status)
		}
	}
}

var jsonMarshaler = protojson.MarshalOptions{
	Multiline:       true,
	Indent:          "  ",
	EmitUnpopulated: true,
}

type keyPresence struct {
	inFirst  bool
	inSecond bool
}

func recordKeyPresence(m map[string]*keyPresence, key []byte, first bool) {
	if len(key) == 0 {
		return
	}

	hexKey := hex.EncodeToString(key)
	entry := m[hexKey]
	if entry == nil {
		entry = &keyPresence{}
		m[hexKey] = entry
	}

	if first {
		entry.inFirst = true
	} else {
		entry.inSecond = true
	}
}

func decodeValue(key []byte, value []byte) string {
	if len(value) == 0 {
		return "<empty>"
	}

	if len(key) == 0 {
		return shortHex(value)
	}

	switch key[0] {
	case store.CLOCK_FRAME:
		return decodeClockValue(key, value)
	case store.KEY_BUNDLE:
		if len(key) < 2 {
			return shortHex(value)
		}
		return decodeKeyBundleValue(key[1], value)
	case store.COIN:
		if len(key) < 2 {
			return shortHex(value)
		}
		return decodeCoinValue(key, key[1], value)
	case store.DATA_PROOF, store.DATA_TIME_PROOF:
		if len(key) < 2 {
			return shortHex(value)
		}
		return decodeDataProofValue(key[0], key[1], value)
	case store.INBOX:
		if len(key) < 2 {
			return shortHex(value)
		}
		return decodeInboxValue(key[1], value)
	case store.HYPERGRAPH_SHARD:
		return decodeHypergraphValue(key, value)
	default:
		return shortHex(value)
	}
}

func decodeClockValue(key []byte, value []byte) string {
	if len(key) < 2 {
		return shortHex(value)
	}

	switch key[1] {
	case store.CLOCK_GLOBAL_FRAME:
		header := &protobufs.GlobalFrameHeader{}
		if s, err := decodeProtoMessage(value, header); err == nil {
			return s
		}
		return shortHex(value)
	case store.CLOCK_GLOBAL_FRAME_REQUEST:
		bundle := &protobufs.MessageBundle{}
		if s, err := decodeProtoMessage(value, bundle); err == nil {
			return s
		}
		return shortHex(value)
	case store.CLOCK_SHARD_FRAME_INDEX_PARENT:
		frame := &protobufs.AppShardFrame{}
		if s, err := decodeProtoMessage(value, frame); err == nil {
			return s
		}
		return shortHex(value)
	case store.CLOCK_SHARD_FRAME_DISTANCE_SHARD:
		dist := new(big.Int).SetBytes(value)
		return fmt.Sprintf("total_distance=%s", dist.String())
	case store.CLOCK_GLOBAL_FRAME_INDEX_EARLIEST,
		store.CLOCK_GLOBAL_FRAME_INDEX_LATEST,
		store.CLOCK_SHARD_FRAME_INDEX_EARLIEST,
		store.CLOCK_SHARD_FRAME_INDEX_LATEST:
		if len(value) == 8 {
			frame := binary.BigEndian.Uint64(value)
			return fmt.Sprintf("frame=%d", frame)
		}
		return shortHex(value)
	default:
		return shortHex(value)
	}
}

func decodeKeyBundleValue(sub byte, value []byte) string {
	switch sub {
	case store.KEY_IDENTITY:
		msg := &protobufs.Ed448PublicKey{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.KEY_PROVING:
		msg := &protobufs.BLS48581SignatureWithProofOfPossession{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.KEY_X448_SIGNED_KEY_BY_ID:
		msg := &protobufs.SignedX448Key{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.KEY_DECAF448_SIGNED_KEY_BY_ID:
		msg := &protobufs.SignedDecaf448Key{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.KEY_CROSS_SIGNATURE:
		if len(value) >= 32 {
			counterparty := shortHex(value[:32])
			signature := shortHex(value[32:])
			return fmt.Sprintf("counterparty=%s\nsignature=%s", counterparty, signature)
		}
	}
	return shortHex(value)
}

func decodeCoinValue(key []byte, sub byte, value []byte) string {
	switch sub {
	case store.COIN_BY_ADDRESS, store.COIN_BY_OWNER:
		if len(value) < 8 {
			return shortHex(value)
		}
		frame := binary.BigEndian.Uint64(value[:8])
		coin := &protobufs.Coin{}
		if s, err := decodeProtoMessage(value[8:], coin); err == nil {
			return fmt.Sprintf("frame=%d\ncoin=%s", frame, s)
		}
	case store.TRANSACTION_BY_ADDRESS, store.TRANSACTION_BY_OWNER:
		tx := &protobufs.MaterializedTransaction{}
		if s, err := decodeProtoMessage(value, tx); err == nil {
			return s
		}
	case store.PENDING_TRANSACTION_BY_ADDRESS, store.PENDING_TRANSACTION_BY_OWNER:
		pending := &protobufs.MaterializedPendingTransaction{}
		if s, err := decodeProtoMessage(value, pending); err == nil {
			return s
		}
	}
	return shortHex(value)
}

func decodeDataProofValue(prefix byte, sub byte, value []byte) string {
	switch prefix {
	case store.DATA_PROOF:
	case store.DATA_TIME_PROOF:
		if len(value) == 0 {
			return "<empty>"
		}
		if len(value) >= 8 {
			increment := binary.BigEndian.Uint32(value[len(value)-4:])
			peer := shortHex(value[:len(value)-4])
			return fmt.Sprintf("peer=%s increment=%d", peer, increment)
		}
	}
	return shortHex(value)
}

func decodeInboxValue(sub byte, value []byte) string {
	switch sub {
	case store.INBOX_MESSAGE:
		msg := &protobufs.InboxMessage{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.INBOX_HUB_ADDS:
		msg := &protobufs.HubAddInboxMessage{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	case store.INBOX_HUB_DELETES:
		msg := &protobufs.HubDeleteInboxMessage{}
		if s, err := decodeProtoMessage(value, msg); err == nil {
			return s
		}
	}
	return shortHex(value)
}

func decodeHypergraphValue(key []byte, value []byte) string {
	if len(value) == 0 {
		return "<empty>"
	}

	if decoded, ok := decodeHypergraphProto(value); ok {
		return decoded
	}

	sub := byte(0)
	if len(key) > 1 {
		sub = key[1]
	}

	switch sub {
	case store.VERTEX_DATA:
		return summarizeVectorCommitmentTree(value)
	case store.VERTEX_TOMBSTONE:
		return shortHex(value)
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE,
		store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		store.VERTEX_ADDS_TREE_ROOT,
		store.VERTEX_REMOVES_TREE_ROOT,
		store.HYPEREDGE_ADDS_TREE_ROOT,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		return summarizeHypergraphTreeNode(value)
	case store.HYPERGRAPH_COVERED_PREFIX:
		return decodeCoveredPrefix(value)
	case store.HYPERGRAPH_COMPLETE:
		if len(value) == 0 {
			return "complete=false"
		}
		return fmt.Sprintf("complete=%t", value[len(value)-1] != 0)
	default:
		return shortHex(value)
	}
}

func decodeHypergraphProto(value []byte) (string, bool) {
	var output string
	var matched bool

	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		fullName := string(mt.Descriptor().FullName())
		lower := strings.ToLower(fullName)
		if !strings.Contains(lower, "hypergraph") &&
			!strings.Contains(lower, "vectorcommitment") &&
			!strings.Contains(lower, "atom") &&
			!strings.Contains(lower, "vertex") &&
			!strings.Contains(lower, "hyperedge") {
			return true
		}

		msg := mt.New().Interface()
		if err := proto.Unmarshal(value, msg); err != nil {
			return true
		}

		hasFields := false
		msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			hasFields = true
			return false
		})
		if !hasFields {
			return true
		}

		jsonBytes, err := jsonMarshaler.Marshal(msg)
		if err != nil {
			return true
		}

		jsonStr := string(jsonBytes)
		if jsonStr == "{}" {
			return true
		}

		output = fmt.Sprintf("%s\n%s", fullName, jsonStr)
		matched = true
		return false
	})

	return output, matched
}

func summarizeVectorCommitmentTree(value []byte) string {
	_, err := tries.DeserializeNonLazyTree(value)
	if err != nil {
		return fmt.Sprintf("vector_commitment_tree decode_error=%v raw=%s", err, shortHex(value))
	}

	sum := sha256.Sum256(value)
	summary := map[string]any{
		"size_bytes": len(value),
		"sha256":     shortHex(sum[:]),
	}
	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Sprintf("vector_commitment_tree size_bytes=%d", len(value))
	}

	return string(jsonBytes)
}

func summarizeHypergraphTreeNode(value []byte) string {
	if len(value) == 0 {
		return "hypergraph_tree_node <empty>"
	}

	hash := sha256.Sum256(value)
	hashStr := shortHex(hash[:])

	reader := bytes.NewReader(value)
	var nodeType byte
	if err := binary.Read(reader, binary.BigEndian, &nodeType); err != nil {
		return fmt.Sprintf("tree_node decode_error=%v sha256=%s", err, hashStr)
	}

	switch nodeType {
	case tries.TypeNil:
		return fmt.Sprintf("tree_nil sha256=%s", hashStr)
	case tries.TypeLeaf:
		leaf, err := tries.DeserializeLeafNode(nil, reader)
		if err != nil {
			return fmt.Sprintf("tree_leaf decode_error=%v sha256=%s", err, hashStr)
		}

		summary := map[string]any{
			"type":         "leaf",
			"key":          shortHex(leaf.Key),
			"value":        shortHex(leaf.Value),
			"hash_target":  shortHex(leaf.HashTarget),
			"commitment":   shortHex(leaf.Commitment),
			"bytes_sha256": hashStr,
		}
		if leaf.Size != nil {
			summary["size"] = leaf.Size.String()
		}

		jsonBytes, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Sprintf("tree_leaf key=%s sha256=%s", shortHex(leaf.Key), hashStr)
		}
		return string(jsonBytes)
	case tries.TypeBranch:
		branch, err := tries.DeserializeBranchNode(nil, reader, true)
		if err != nil {
			return fmt.Sprintf("tree_branch decode_error=%v sha256=%s", err, hashStr)
		}

		childSummary := map[string]int{
			"branch": 0,
			"leaf":   0,
			"nil":    0,
		}
		for _, child := range branch.Children {
			switch child.(type) {
			case *tries.LazyVectorCommitmentBranchNode:
				childSummary["branch"]++
			case *tries.LazyVectorCommitmentLeafNode:
				childSummary["leaf"]++
			default:
				childSummary["nil"]++
			}
		}

		summary := map[string]any{
			"type":           "branch",
			"prefix":         branch.Prefix,
			"leaf_count":     branch.LeafCount,
			"longest_branch": branch.LongestBranch,
			"commitment":     shortHex(branch.Commitment),
			"children":       childSummary,
			"bytes_sha256":   hashStr,
		}
		if branch.Size != nil {
			summary["size"] = branch.Size.String()
		}

		jsonBytes, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Sprintf(
				"tree_branch prefix=%v leafs=%d sha256=%s",
				branch.Prefix,
				branch.LeafCount,
				hashStr,
			)
		}
		return string(jsonBytes)
	default:
		return fmt.Sprintf(
			"tree_node type=0x%02x payload=%s sha256=%s",
			nodeType,
			shortHex(value[1:]),
			hashStr,
		)
	}
}

func decodeCoveredPrefix(value []byte) string {
	if len(value)%8 != 0 {
		return shortHex(value)
	}

	result := make([]int64, len(value)/8)
	for i := range result {
		result[i] = int64(binary.BigEndian.Uint64(value[i*8 : (i+1)*8]))
	}

	return fmt.Sprintf("covered_prefix=%v", result)
}

func decodeProtoMessage(data []byte, msg proto.Message) (string, error) {
	if err := proto.Unmarshal(data, msg); err != nil {
		return "", err
	}
	encoded, err := jsonMarshaler.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func diffStrings(a string, b string) string {
	if a == b {
		return ""
	}

	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")

	countA := map[string]int{}
	countB := map[string]int{}
	for _, line := range linesA {
		countA[line]++
	}
	for _, line := range linesB {
		countB[line]++
	}

	unique := map[string]struct{}{}
	for line := range countA {
		unique[line] = struct{}{}
	}
	for line := range countB {
		unique[line] = struct{}{}
	}

	var diffs []string
	keys := make([]string, 0, len(unique))
	for line := range unique {
		keys = append(keys, line)
	}
	sort.Strings(keys)
	for _, line := range keys {
		diff := countB[line] - countA[line]
		switch {
		case diff > 0:
			for i := 0; i < diff; i++ {
				diffs = append(diffs, "+ "+line)
			}
		case diff < 0:
			for i := 0; i < -diff; i++ {
				diffs = append(diffs, "- "+line)
			}
		}
	}

	return strings.Join(diffs, "\n")
}

func indent(value string) string {
	if value == "" {
		return ""
	}
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

func describeKey(key []byte) string {
	if len(key) == 0 {
		return "empty key"
	}

	switch key[0] {
	case store.CLOCK_FRAME:
		return describeClockKey(key)
	case store.PROVING_KEY:
		return "legacy proving key entry"
	case store.PROVING_KEY_STAGED:
		return "legacy staged proving key entry"
	case store.KEY_BUNDLE:
		return describeKeyBundleKey(key)
	case store.DATA_PROOF:
		return describeDataProofKey(key)
	case store.DATA_TIME_PROOF:
		return describeDataTimeProofKey(key)
	case store.PEERSTORE:
		return describePeerstoreKey(key)
	case store.COIN:
		return describeCoinKey(key)
	case store.PROOF:
		return "proof store entry (unused)"
	case store.HYPERGRAPH_SHARD:
		return describeHypergraphKey(key)
	case store.SHARD:
		return describeShardKey(key)
	case store.INBOX:
		return describeInboxKey(key)
	case store.WORKER:
		return describeWorkerKey(key)
	default:
		return fmt.Sprintf("unknown prefix 0x%02x (len=%d)", key[0], len(key))
	}
}

func describeClockKey(key []byte) string {
	if len(key) < 2 {
		return "clock: invalid key length"
	}

	sub := key[1]
	switch sub {
	case store.CLOCK_GLOBAL_FRAME:
		if len(key) >= 10 {
			frame := binary.BigEndian.Uint64(key[2:10])
			return fmt.Sprintf("clock global frame header frame=%d", frame)
		}
		return "clock global frame header (invalid length)"
	case store.CLOCK_SHARD_FRAME_SHARD:
		if len(key) >= 10 {
			frame := binary.BigEndian.Uint64(key[2:10])
			filter := key[10:]
			return fmt.Sprintf(
				"clock shard frame pointer frame=%d shard=%s",
				frame,
				shortHex(filter),
			)
		}
		return "clock shard frame pointer (invalid length)"
	case store.CLOCK_GLOBAL_FRAME_REQUEST:
		if len(key) >= 12 {
			frame := binary.BigEndian.Uint64(key[2:10])
			req := binary.BigEndian.Uint16(key[10:12])
			return fmt.Sprintf(
				"clock global frame request frame=%d index=%d",
				frame,
				req,
			)
		}
		return "clock global frame request (invalid length)"
	case store.CLOCK_GLOBAL_FRAME_INDEX_EARLIEST:
		return "clock global frame earliest index"
	case store.CLOCK_GLOBAL_FRAME_INDEX_LATEST:
		return "clock global frame latest index"
	case store.CLOCK_GLOBAL_FRAME_INDEX_PARENT:
		if len(key) >= 12 {
			frame := binary.BigEndian.Uint64(key[2:10])
			parent := key[10:]
			return fmt.Sprintf(
				"clock global frame parent index frame=%d parent=%s",
				frame,
				shortHex(parent),
			)
		}
		return "clock global frame parent index (invalid length)"
	case store.CLOCK_SHARD_FRAME_INDEX_EARLIEST:
		return fmt.Sprintf(
			"clock shard frame earliest index shard=%s",
			shortHex(key[2:]),
		)
	case store.CLOCK_SHARD_FRAME_INDEX_LATEST:
		return fmt.Sprintf(
			"clock shard frame latest index shard=%s",
			shortHex(key[2:]),
		)
	case store.CLOCK_SHARD_FRAME_INDEX_PARENT:
		if len(key) >= 42 {
			frame := binary.BigEndian.Uint64(key[2:10])
			filter := key[10 : len(key)-32]
			selector := key[len(key)-32:]
			return fmt.Sprintf(
				"clock shard parent index frame=%d shard=%s selector=%s",
				frame,
				shortHex(filter),
				shortHex(selector),
			)
		}
		return "clock shard parent index (invalid length)"
	case store.CLOCK_SHARD_FRAME_FRECENCY_SHARD:
		if len(key) >= 12 {
			ring := binary.BigEndian.Uint16(key[2:4])
			frame := binary.BigEndian.Uint64(key[4:12])
			filter := key[12:]
			return fmt.Sprintf(
				"clock shard prover trie ring=%d frame=%d shard=%s",
				ring,
				frame,
				shortHex(filter),
			)
		}
		return "clock shard prover trie (invalid length)"
	case store.CLOCK_SHARD_FRAME_DISTANCE_SHARD:
		if len(key) >= 42 {
			frame := binary.BigEndian.Uint64(key[2:10])
			filter := key[10 : len(key)-32]
			selector := key[len(key)-32:]
			return fmt.Sprintf(
				"clock shard total distance frame=%d shard=%s selector=%s",
				frame,
				shortHex(filter),
				shortHex(selector),
			)
		}
		return "clock shard total distance (invalid length)"
	case store.CLOCK_SHARD_FRAME_SENIORITY_SHARD:
		return fmt.Sprintf(
			"clock shard seniority map shard=%s",
			shortHex(key[2:]),
		)
	case store.CLOCK_SHARD_FRAME_STATE_TREE:
		return fmt.Sprintf(
			"clock shard state tree shard=%s",
			shortHex(key[2:]),
		)
	case store.CLOCK_COMPACTION_SHARD:
		return fmt.Sprintf(
			"clock compaction marker shard=%s",
			shortHex(key[2:]),
		)
	case store.CLOCK_SHARD_FRAME_CANDIDATE_SHARD:
		return fmt.Sprintf("clock shard candidate frame raw=%s", shortHex(key))
	case store.CLOCK_SHARD_FRAME_CANDIDATE_INDEX_LATEST:
		return fmt.Sprintf(
			"clock shard candidate latest index shard=%s",
			shortHex(key[2:]),
		)
	default:
		return fmt.Sprintf(
			"clock unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(key),
		)
	}
}

func describeKeyBundleKey(key []byte) string {
	if len(key) < 2 {
		return "key bundle: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.KEY_DATA:
		return fmt.Sprintf("key bundle metadata raw=%s", shortHex(payload))
	case store.KEY_BUNDLE_INDEX_EARLIEST:
		return "key bundle earliest index"
	case store.KEY_BUNDLE_INDEX_LATEST:
		return "key bundle latest index"
	case store.KEY_IDENTITY:
		return fmt.Sprintf("identity key address=%s", shortHex(payload))
	case store.KEY_PROVING:
		return fmt.Sprintf("proving key address=%s", shortHex(payload))
	case store.KEY_CROSS_SIGNATURE:
		return fmt.Sprintf("cross signature signer=%s", shortHex(payload))
	case store.KEY_X448_SIGNED_KEY_BY_ID:
		return fmt.Sprintf("signed X448 key address=%s", shortHex(payload))
	case store.KEY_X448_SIGNED_KEY_BY_PARENT:
		if len(payload) >= 72 {
			parent := payload[:32]
			purpose := payload[32:40]
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed X448 key by parent parent=%s purpose=%s key=%s",
				shortHex(parent),
				strings.TrimRight(string(purpose), "\x00"),
				shortHex(child),
			)
		}
		return "signed X448 key by parent (invalid length)"
	case store.KEY_X448_SIGNED_KEY_BY_PURPOSE:
		if len(payload) >= 40 {
			purpose := payload[:8]
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed X448 key by purpose purpose=%s key=%s",
				strings.TrimRight(string(purpose), "\x00"),
				shortHex(child),
			)
		}
		return "signed X448 key by purpose (invalid length)"
	case store.KEY_X448_SIGNED_KEY_BY_EXPIRY:
		if len(payload) >= 40 {
			expiry := binary.BigEndian.Uint64(payload[:8])
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed X448 key by expiry expiry=%d key=%s",
				expiry,
				shortHex(child),
			)
		}
		return "signed X448 key by expiry (invalid length)"
	case store.KEY_DECAF448_SIGNED_KEY_BY_ID:
		return fmt.Sprintf("signed Decaf448 key address=%s", shortHex(payload))
	case store.KEY_DECAF448_SIGNED_KEY_BY_PARENT:
		if len(payload) >= 72 {
			parent := payload[:32]
			purpose := payload[32:40]
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed Decaf448 key by parent parent=%s purpose=%s key=%s",
				shortHex(parent),
				strings.TrimRight(string(purpose), "\x00"),
				shortHex(child),
			)
		}
		return "signed Decaf448 key by parent (invalid length)"
	case store.KEY_DECAF448_SIGNED_KEY_BY_PURPOSE:
		if len(payload) >= 40 {
			purpose := payload[:8]
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed Decaf448 key by purpose purpose=%s key=%s",
				strings.TrimRight(string(purpose), "\x00"),
				shortHex(child),
			)
		}
		return "signed Decaf448 key by purpose (invalid length)"
	case store.KEY_DECAF448_SIGNED_KEY_BY_EXPIRY:
		if len(payload) >= 40 {
			expiry := binary.BigEndian.Uint64(payload[:8])
			child := payload[len(payload)-32:]
			return fmt.Sprintf(
				"signed Decaf448 key by expiry expiry=%d key=%s",
				expiry,
				shortHex(child),
			)
		}
		return "signed Decaf448 key by expiry (invalid length)"
	case store.KEY_DEVICE_PRE_KEY_BY_ID:
		return fmt.Sprintf("device pre-key by id key=%s", shortHex(payload))
	case store.KEY_DEVICE_PRE_KEY_BY_DEVICE:
		return fmt.Sprintf("device pre-key by device id=%s", shortHex(payload))
	case store.KEY_DEVICE_PRE_KEY_AVAILABLE:
		return fmt.Sprintf("device pre-key availability marker=%s", shortHex(payload))
	case store.KEY_DEVICE_PRE_KEY_ONE_TIME:
		return fmt.Sprintf("device pre-key one-time marker=%s", shortHex(payload))
	default:
		return fmt.Sprintf(
			"key bundle unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeDataProofKey(key []byte) string {
	if len(key) < 2 {
		return "data proof: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.DATA_PROOF_SEGMENT:
		if len(payload) >= 32 {
			hash := payload[:32]
			filter := payload[32:]
			return fmt.Sprintf(
				"data proof segment hash=%s filter=%s",
				shortHex(hash),
				shortHex(filter),
			)
		}
		return "data proof segment (invalid length)"
	case store.DATA_TIME_PROOF_DATA:
		if len(payload) >= 36 {
			peer := payload[:32]
			increment := binary.BigEndian.Uint32(payload[32:36])
			return fmt.Sprintf(
				"data time proof peer=%s increment=%d",
				shortHex(peer),
				increment,
			)
		}
		return "data time proof data (invalid length)"
	case store.DATA_TIME_PROOF_LATEST:
		return fmt.Sprintf(
			"data time proof latest peer=%s",
			shortHex(payload),
		)
	default:
		return fmt.Sprintf(
			"data proof unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeDataTimeProofKey(key []byte) string {
	return describeDataProofKey(key)
}

func describePeerstoreKey(key []byte) string {
	if len(key) < 2 {
		return "peerstore: invalid key length"
	}

	return fmt.Sprintf("peerstore entry key=%q", string(key[1:]))
}

func describeCoinKey(key []byte) string {
	if len(key) < 2 {
		return "coin store: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.COIN_BY_ADDRESS:
		return fmt.Sprintf("coin by address address=%s", shortHex(payload))
	case store.COIN_BY_OWNER:
		if len(payload) >= 64 {
			owner := payload[:len(payload)-32]
			address := payload[len(payload)-32:]
			return fmt.Sprintf(
				"coin by owner owner=%s address=%s",
				shortHex(owner),
				shortHex(address),
			)
		}
		return fmt.Sprintf("coin by owner raw=%s", shortHex(payload))
	case store.TRANSACTION_BY_ADDRESS:
		if len(payload) >= 32 {
			address := payload[len(payload)-32:]
			domain := payload[:len(payload)-32]
			return fmt.Sprintf(
				"transaction by address domain=%s address=%s",
				shortHex(domain),
				shortHex(address),
			)
		}
		return fmt.Sprintf("transaction by address raw=%s", shortHex(payload))
	case store.TRANSACTION_BY_OWNER:
		if len(payload) >= 64 {
			address := payload[len(payload)-32:]
			owner := payload[len(payload)-64 : len(payload)-32]
			domain := payload[:len(payload)-64]
			return fmt.Sprintf(
				"transaction by owner domain=%s owner=%s address=%s",
				shortHex(domain),
				shortHex(owner),
				shortHex(address),
			)
		}
		return fmt.Sprintf("transaction by owner raw=%s", shortHex(payload))
	case store.PENDING_TRANSACTION_BY_ADDRESS:
		if len(payload) >= 32 {
			address := payload[len(payload)-32:]
			domain := payload[:len(payload)-32]
			return fmt.Sprintf(
				"pending transaction by address domain=%s address=%s",
				shortHex(domain),
				shortHex(address),
			)
		}
		return fmt.Sprintf(
			"pending transaction by address raw=%s",
			shortHex(payload),
		)
	case store.PENDING_TRANSACTION_BY_OWNER:
		if len(payload) >= 64 {
			address := payload[len(payload)-32:]
			owner := payload[len(payload)-64 : len(payload)-32]
			domain := payload[:len(payload)-64]
			return fmt.Sprintf(
				"pending transaction by owner domain=%s owner=%s address=%s",
				shortHex(domain),
				shortHex(owner),
				shortHex(address),
			)
		}
		return fmt.Sprintf(
			"pending transaction by owner raw=%s",
			shortHex(payload),
		)
	default:
		return fmt.Sprintf(
			"coin store unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeHypergraphKey(key []byte) string {
	if len(key) < 2 {
		return "hypergraph: invalid key length"
	}

	if len(key) >= 10 {
		switch key[9] {
		case store.HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT,
			store.HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT,
			store.HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT,
			store.HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT:
			frame := binary.BigEndian.Uint64(key[1:9])
			shard := key[10:]
			var setPhase string
			switch key[9] {
			case store.HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT:
				setPhase = "vertex-adds"
			case store.HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT:
				setPhase = "vertex-removes"
			case store.HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT:
				setPhase = "hyperedge-adds"
			case store.HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT:
				setPhase = "hyperedge-removes"
			}
			return fmt.Sprintf(
				"hypergraph shard commit %s frame=%d shard=%s",
				setPhase,
				frame,
				shortHex(shard),
			)
		}
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.VERTEX_DATA:
		return fmt.Sprintf("hypergraph vertex data id=%s", shortHex(payload))
	case store.VERTEX_TOMBSTONE:
		return fmt.Sprintf("hypergraph vertex tombstone id=%s", shortHex(payload))
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			node := payload[35:]
			return fmt.Sprintf(
				"%s tree node shard=[%s|%s] node=%s",
				describeHypergraphTreeType(sub),
				shortHex(l1),
				shortHex(l2),
				shortHex(node),
			)
		}
		return fmt.Sprintf(
			"%s tree node (invalid length)",
			describeHypergraphTreeType(sub),
		)
	case store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			path := parseUint64Path(payload[35:])
			return fmt.Sprintf(
				"%s path shard=[%s|%s] path=%v",
				describeHypergraphTreeType(sub),
				shortHex(l1),
				shortHex(l2),
				path,
			)
		}
		return fmt.Sprintf(
			"%s path (invalid length)",
			describeHypergraphTreeType(sub),
		)
	case store.VERTEX_ADDS_CHANGE_RECORD,
		store.VERTEX_REMOVES_CHANGE_RECORD,
		store.HYPEREDGE_ADDS_CHANGE_RECORD,
		store.HYPEREDGE_REMOVES_CHANGE_RECORD:
		if len(payload) >= 43 {
			l1 := payload[:3]
			l2 := payload[3:35]
			frame := binary.BigEndian.Uint64(payload[35:43])
			recordKey := payload[43:]
			return fmt.Sprintf(
				"%s change record shard=[%s|%s] frame=%d key=%s",
				describeHypergraphTreeType(sub),
				shortHex(l1),
				shortHex(l2),
				frame,
				shortHex(recordKey),
			)
		}
		return fmt.Sprintf(
			"%s change record (invalid length)",
			describeHypergraphTreeType(sub),
		)
	case store.VERTEX_ADDS_TREE_ROOT,
		store.VERTEX_REMOVES_TREE_ROOT,
		store.HYPEREDGE_ADDS_TREE_ROOT,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			return fmt.Sprintf(
				"%s tree root shard=[%s|%s]",
				describeHypergraphTreeType(sub),
				shortHex(l1),
				shortHex(l2),
			)
		}
		return fmt.Sprintf(
			"%s tree root (invalid length)",
			describeHypergraphTreeType(sub),
		)
	case store.HYPERGRAPH_COVERED_PREFIX:
		return "hypergraph covered prefix metadata"
	case store.HYPERGRAPH_COMPLETE:
		return "hypergraph completeness flag"
	default:
		return fmt.Sprintf(
			"hypergraph unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeHypergraphTreeType(kind byte) string {
	switch kind {
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_ADDS_CHANGE_RECORD,
		store.VERTEX_ADDS_TREE_ROOT:
		return "vertex adds"
	case store.VERTEX_REMOVES_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_CHANGE_RECORD,
		store.VERTEX_REMOVES_TREE_ROOT:
		return "vertex removes"
	case store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_CHANGE_RECORD,
		store.HYPEREDGE_ADDS_TREE_ROOT:
		return "hyperedge adds"
	case store.HYPEREDGE_REMOVES_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_CHANGE_RECORD,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		return "hyperedge removes"
	default:
		return "hypergraph"
	}
}

func describeShardKey(key []byte) string {
	if len(key) < 2 {
		return "shard store: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.APP_SHARD_DATA:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			path := parseUint32Path(payload[35:])
			return fmt.Sprintf(
				"application shard shard=[%s|%s] path=%v",
				shortHex(l1),
				shortHex(l2),
				path,
			)
		}
		return "application shard data (invalid length)"
	default:
		return fmt.Sprintf(
			"shard store unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeInboxKey(key []byte) string {
	if len(key) < 2 {
		return "inbox store: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.INBOX_MESSAGE:
		if len(payload) >= 75 {
			filter := payload[:3]
			timestamp := binary.BigEndian.Uint64(payload[3:11])
			addressHash := payload[11:43]
			messageHash := payload[43:75]
			return fmt.Sprintf(
				"inbox message filter=%v timestamp=%d addr_hash=%s msg_hash=%s",
				filter,
				timestamp,
				shortHex(addressHash),
				shortHex(messageHash),
			)
		}
		return "inbox message (invalid length)"
	case store.INBOX_MESSAGE_DATA:
		return fmt.Sprintf("inbox message payload reference=%s", shortHex(payload))
	case store.INBOX_MESSAGE_BY_ADDR:
		return fmt.Sprintf("inbox message by address=%s", shortHex(payload))
	case store.INBOX_HUB_BY_ADDR:
		if len(payload) >= 3 {
			filter := payload[:3]
			hub := payload[3:]
			return fmt.Sprintf(
				"inbox hub materialized filter=%v hub=%s",
				filter,
				shortHex(hub),
			)
		}
		return "inbox hub materialized (invalid length)"
	case store.INBOX_HUB_ADDS, store.INBOX_HUB_DELETES:
		if len(payload) >= 35 {
			filter := payload[:3]
			addressHash := payload[3:35]
			if len(payload) >= 35 {
				rest := payload[35:]
				half := len(rest) / 2
				hubKey := rest[:half]
				inboxKey := rest[half:]
				action := "add"
				if sub == store.INBOX_HUB_DELETES {
					action = "delete"
				}
				return fmt.Sprintf(
					"inbox hub %s filter=%v addr_hash=%s hub_key=%s inbox_key=%s",
					action,
					filter,
					shortHex(addressHash),
					shortHex(hubKey),
					shortHex(inboxKey),
				)
			}
		}
		return "inbox hub operation (invalid length)"
	default:
		return fmt.Sprintf(
			"inbox store unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func describeWorkerKey(key []byte) string {
	if len(key) < 2 {
		return "worker store: invalid key length"
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.WORKER_BY_CORE:
		if len(payload) >= 8 {
			core := binary.BigEndian.Uint64(payload[:8])
			return fmt.Sprintf("worker by core core_id=%d", core)
		}
		return "worker by core (invalid length)"
	case store.WORKER_BY_FILTER:
		return fmt.Sprintf("worker by filter filter=%s", shortHex(payload))
	default:
		return fmt.Sprintf(
			"worker store unknown subtype 0x%02x raw=%s",
			sub,
			shortHex(payload),
		)
	}
}

func shortHex(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	if len(b) <= 16 {
		return "0x" + hex.EncodeToString(b)
	}
	return fmt.Sprintf(
		"0x%s…%s(len=%d)",
		hex.EncodeToString(b[:8]),
		hex.EncodeToString(b[len(b)-8:]),
		len(b),
	)
}

func parseUint32Path(b []byte) []uint32 {
	if len(b)%4 != 0 {
		return nil
	}

	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(b[i*4 : (i+1)*4])
	}
	return out
}

func parseUint64Path(b []byte) []uint64 {
	if len(b)%8 != 0 {
		return nil
	}

	out := make([]uint64, len(b)/8)
	for i := range out {
		out[i] = binary.BigEndian.Uint64(b[i*8 : (i+1)*8])
	}
	return out
}
