package realbatch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidon2native "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	gnarkhash "github.com/consensys/gnark/std/hash"
	sha2circuit "github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
	poseidon2circuit "github.com/consensys/gnark/std/permutation/poseidon2"
)

const ProfileName = "groth16_bls12_381_poseidon_v1"

var queueConsumeMagic = []uint8{'V', 'S', 'C', 'Q', 'C', 0x01}
var queuePrefixCommitmentMagic = []uint8{'V', 'S', 'C', 'Q', 'P', 0x01}

type PoseidonBatchTransitionCircuit struct {
	SidechainID           frontend.Variable `gnark:",public"`
	BatchNumber           frontend.Variable `gnark:",public"`
	PriorStateRoot        frontend.Variable `gnark:",public"`
	NewStateRoot          frontend.Variable `gnark:",public"`
	L1MessageRootBefore   frontend.Variable `gnark:",public"`
	L1MessageRootAfter    frontend.Variable `gnark:",public"`
	ConsumedQueueMessages frontend.Variable `gnark:",public"`
	QueuePrefixCommitment frontend.Variable `gnark:",public"`
	WithdrawalRoot        frontend.Variable `gnark:",public"`
	DataRoot              frontend.Variable `gnark:",public"`
	DataSize              frontend.Variable `gnark:",public"`

	ConsumedEntryPresent     frontend.Variable
	ConsumedEntryQueueIndex  frontend.Variable
	ConsumedEntryMessageKind frontend.Variable
	ConsumedEntryMessageID   [32]uints.U8
	ConsumedEntryMessageHash [32]uints.U8
}

func (c *PoseidonBatchTransitionCircuit) Define(api frontend.API) error {
	if err := assertExperimentalQueueWitness(api, c); err != nil {
		return err
	}

	transitionHasher, err := newPoseidonHasher(api)
	if err != nil {
		return err
	}
	transitionHasher.Write(
		c.SidechainID,
		c.BatchNumber,
		c.PriorStateRoot,
		c.L1MessageRootBefore,
		c.L1MessageRootAfter,
		c.ConsumedQueueMessages,
		c.QueuePrefixCommitment,
		c.DataRoot,
		c.DataSize,
	)
	transitionCommitment := transitionHasher.Sum()

	stateHasher, err := newPoseidonHasher(api)
	if err != nil {
		return err
	}
	stateHasher.Write(c.PriorStateRoot, transitionCommitment)
	api.AssertIsEqual(c.NewStateRoot, stateHasher.Sum())

	withdrawalHasher, err := newPoseidonHasher(api)
	if err != nil {
		return err
	}
	withdrawalHasher.Write(c.NewStateRoot, transitionCommitment, c.DataRoot)
	api.AssertIsEqual(c.WithdrawalRoot, withdrawalHasher.Sum())

	return nil
}

func BuildAssignment(request toybatch.CommandRequest) (PoseidonBatchTransitionCircuit, error) {
	if err := validatePublishedDataWitness(request); err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}

	sidechainID, err := parseUintAsField(request.SidechainID, "sidechain_id")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	batchNumber, err := parseUintAsField(uint64(request.PublicInputs.BatchNumber), "batch_number")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	priorStateRoot, err := parseFieldHex(request.PublicInputs.PriorStateRoot, "prior_state_root")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	newStateRoot, err := parseFieldHex(request.PublicInputs.NewStateRoot, "new_state_root")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	l1MessageRootBefore, err := parseFieldHex(request.PublicInputs.L1MessageRootBefore, "l1_message_root_before")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	l1MessageRootAfter, err := parseFieldHex(request.PublicInputs.L1MessageRootAfter, "l1_message_root_after")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	consumedQueueMessages, err := parseUintAsField(uint64(request.PublicInputs.ConsumedQueueMessages), "consumed_queue_messages")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	queuePrefixCommitment, err := parseFieldHex(request.PublicInputs.QueuePrefixCommitment, "queue_prefix_commitment")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	withdrawalRoot, err := parseFieldHex(request.PublicInputs.WithdrawalRoot, "withdrawal_root")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	dataRoot, err := parseFieldHex(request.PublicInputs.DataRoot, "data_root")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}
	dataSize, err := parseUintAsField(uint64(request.PublicInputs.DataSize), "data_size")
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}

	consumedEntryPresent, consumedEntryQueueIndex, consumedEntryMessageKind, consumedEntryMessageID, consumedEntryMessageHash, err :=
		buildConsumedQueueWitness(request)
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}

	return PoseidonBatchTransitionCircuit{
		SidechainID:               sidechainID,
		BatchNumber:               batchNumber,
		PriorStateRoot:            priorStateRoot,
		NewStateRoot:              newStateRoot,
		L1MessageRootBefore:       l1MessageRootBefore,
		L1MessageRootAfter:        l1MessageRootAfter,
		ConsumedQueueMessages:     consumedQueueMessages,
		QueuePrefixCommitment:     queuePrefixCommitment,
		WithdrawalRoot:            withdrawalRoot,
		DataRoot:                  dataRoot,
		DataSize:                  dataSize,
		ConsumedEntryPresent:      consumedEntryPresent,
		ConsumedEntryQueueIndex:   consumedEntryQueueIndex,
		ConsumedEntryMessageKind:  consumedEntryMessageKind,
		ConsumedEntryMessageID:    consumedEntryMessageID,
		ConsumedEntryMessageHash:  consumedEntryMessageHash,
	}, nil
}

func DeriveRequest(request toybatch.CommandRequest) (toybatch.CommandRequest, error) {
	cleared := ensureDerivedTargetsCleared(request)
	if len(request.DataChunksHex) != 0 {
		chunks, err := decodeDataChunks(request.DataChunksHex)
		if err != nil {
			return toybatch.CommandRequest{}, err
		}
		cleared.PublicInputs.DataRoot = computePublishedDataRoot(chunks)
		cleared.PublicInputs.DataSize = uint32(computePublishedDataSize(chunks))
	}
	assignment, err := BuildAssignment(cleared)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}

	newStateRoot, err := poseidonHash(
		assignment.PriorStateRoot.(*big.Int),
		mustTransitionCommitment(assignment),
	)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	withdrawalRoot, err := poseidonHash(
		newStateRoot,
		mustTransitionCommitment(assignment),
		assignment.DataRoot.(*big.Int),
	)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}

	derived := request
	if len(request.DataChunksHex) != 0 {
		chunks, err := decodeDataChunks(request.DataChunksHex)
		if err != nil {
			return toybatch.CommandRequest{}, err
		}
		derived.PublicInputs.DataRoot = computePublishedDataRoot(chunks)
		derived.PublicInputs.DataSize = uint32(computePublishedDataSize(chunks))
	}
	derived.PublicInputs.NewStateRoot = formatFieldHex(newStateRoot)
	derived.PublicInputs.WithdrawalRoot = formatFieldHex(withdrawalRoot)
	return derived, nil
}

func ValidateDerivedRequest(request toybatch.CommandRequest) error {
	derived, err := DeriveRequest(request)
	if err != nil {
		return err
	}
	if err := validatePublishedDataWitness(request); err != nil {
		return err
	}
	if normalizeHex(request.PublicInputs.NewStateRoot) != normalizeHex(derived.PublicInputs.NewStateRoot) {
		return fmt.Errorf("new_state_root does not match derived Poseidon transition")
	}
	if normalizeHex(request.PublicInputs.WithdrawalRoot) != normalizeHex(derived.PublicInputs.WithdrawalRoot) {
		return fmt.Errorf("withdrawal_root does not match derived Poseidon transition")
	}
	return nil
}

func validatePublishedDataWitness(request toybatch.CommandRequest) error {
	if len(request.DataChunksHex) == 0 {
		return nil
	}

	chunks, err := decodeDataChunks(request.DataChunksHex)
	if err != nil {
		return err
	}
	expectedSize := computePublishedDataSize(chunks)
	if uint32(expectedSize) != request.PublicInputs.DataSize {
		return fmt.Errorf("data_size does not match provided data_chunks_hex")
	}
	expectedRoot := computePublishedDataRoot(chunks)
	if normalizeHex(request.PublicInputs.DataRoot) != normalizeHex(expectedRoot) {
		return fmt.Errorf("data_root does not match provided data_chunks_hex")
	}
	return nil
}

func ensureDerivedTargetsCleared(request toybatch.CommandRequest) toybatch.CommandRequest {
	request.PublicInputs.NewStateRoot = "0"
	request.PublicInputs.WithdrawalRoot = "0"
	return request
}

func mustTransitionCommitment(assignment PoseidonBatchTransitionCircuit) *big.Int {
	commitment, err := poseidonHash(
		assignment.SidechainID.(*big.Int),
		assignment.BatchNumber.(*big.Int),
		assignment.PriorStateRoot.(*big.Int),
		assignment.L1MessageRootBefore.(*big.Int),
		assignment.L1MessageRootAfter.(*big.Int),
		assignment.ConsumedQueueMessages.(*big.Int),
		assignment.QueuePrefixCommitment.(*big.Int),
		assignment.DataRoot.(*big.Int),
		assignment.DataSize.(*big.Int),
	)
	if err != nil {
		panic(err)
	}
	return commitment
}

func assertExperimentalQueueWitness(api frontend.API, circuit *PoseidonBatchTransitionCircuit) error {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	u64api, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	api.AssertIsBoolean(circuit.ConsumedEntryPresent)
	api.AssertIsEqual(circuit.ConsumedQueueMessages, circuit.ConsumedEntryPresent)

	l1MessageRootBefore := fieldToLittleEndianBytes(api, bapi, circuit.L1MessageRootBefore)
	l1MessageRootAfter := fieldToLittleEndianBytes(api, bapi, circuit.L1MessageRootAfter)
	queuePrefixCommitment := fieldToLittleEndianBytes(api, bapi, circuit.QueuePrefixCommitment)
	zeroRoot := zeroByteArray32()

	consumePreimage := buildQueueStepPreimage(
		bapi,
		u64api,
		queueConsumeMagic,
		circuit.SidechainID,
		l1MessageRootBefore,
		circuit.ConsumedEntryQueueIndex,
		circuit.ConsumedEntryMessageKind,
		circuit.ConsumedEntryMessageID,
		circuit.ConsumedEntryMessageHash,
	)
	consumedRoot, err := doubleSHA256(api, consumePreimage)
	if err != nil {
		return err
	}

	prefixPreimage := buildQueueStepPreimage(
		bapi,
		u64api,
		queuePrefixCommitmentMagic,
		circuit.SidechainID,
		zeroRoot,
		circuit.ConsumedEntryQueueIndex,
		circuit.ConsumedEntryMessageKind,
		circuit.ConsumedEntryMessageID,
		circuit.ConsumedEntryMessageHash,
	)
	prefixCommitment, err := doubleSHA256(api, prefixPreimage)
	if err != nil {
		return err
	}

	expectedAfter := selectByteArray32(bapi, circuit.ConsumedEntryPresent, consumedRoot, l1MessageRootBefore)
	expectedPrefix := selectByteArray32(bapi, circuit.ConsumedEntryPresent, prefixCommitment, zeroRoot)
	assertByteArray32Equal(bapi, expectedAfter, l1MessageRootAfter)
	assertByteArray32Equal(bapi, expectedPrefix, queuePrefixCommitment)
	return nil
}

func buildQueueStepPreimage(
	bapi *uints.Bytes,
	u64api *uints.BinaryField[uints.U64],
	magic []uint8,
	sidechainID frontend.Variable,
	prior [32]uints.U8,
	queueIndex frontend.Variable,
	messageKind frontend.Variable,
	messageID [32]uints.U8,
	messageHash [32]uints.U8,
) []uints.U8 {
	preimage := make([]uints.U8, 0, len(magic)+1+32+8+1+32+32)
	preimage = append(preimage, uints.NewU8Array(magic)...)
	preimage = append(preimage, bapi.ValueOf(sidechainID))
	preimage = append(preimage, prior[:]...)
	preimage = append(preimage, u64api.UnpackLSB(u64api.ValueOf(queueIndex))...)
	preimage = append(preimage, bapi.ValueOf(messageKind))
	preimage = append(preimage, messageID[:]...)
	preimage = append(preimage, messageHash[:]...)
	return preimage
}

func doubleSHA256(api frontend.API, preimage []uints.U8) ([32]uints.U8, error) {
	var digest [32]uints.U8

	firstRound, err := sha2circuit.New(api)
	if err != nil {
		return digest, err
	}
	firstRound.Write(preimage)
	first := firstRound.Sum()

	secondRound, err := sha2circuit.New(api)
	if err != nil {
		return digest, err
	}
	secondRound.Write(first)
	second := secondRound.Sum()
	copy(digest[:], second)
	return digest, nil
}

func selectByteArray32(bapi *uints.Bytes, selector frontend.Variable, whenTrue, whenFalse [32]uints.U8) [32]uints.U8 {
	var out [32]uints.U8
	for i := range out {
		out[i] = bapi.Select(selector, whenTrue[i], whenFalse[i])
	}
	return out
}

func assertByteArray32Equal(bapi *uints.Bytes, lhs, rhs [32]uints.U8) {
	for i := range lhs {
		bapi.AssertIsEqual(lhs[i], rhs[i])
	}
}

func zeroByteArray32() [32]uints.U8 {
	var out [32]uints.U8
	for i := range out {
		out[i] = uints.NewU8(0)
	}
	return out
}

func fieldToLittleEndianBytes(api frontend.API, bapi *uints.Bytes, value frontend.Variable) [32]uints.U8 {
	var out [32]uints.U8
	bitsLE := bits.ToBinary(api, value, bits.WithNbDigits(256))
	for i := 0; i < 32; i++ {
		out[i] = bapi.ValueOf(bits.FromBinary(api, bitsLE[i*8:(i+1)*8]))
	}
	return out
}

func buildConsumedQueueWitness(request toybatch.CommandRequest) (frontend.Variable, frontend.Variable, frontend.Variable, [32]uints.U8, [32]uints.U8, error) {
	var messageID [32]uints.U8
	var messageHash [32]uints.U8

	if len(request.ConsumedQueueEntries) > 1 {
		return nil, nil, nil, messageID, messageHash, fmt.Errorf("experimental real profile supports at most one consumed queue entry")
	}
	if len(request.ConsumedQueueEntries) != int(request.PublicInputs.ConsumedQueueMessages) {
		return nil, nil, nil, messageID, messageHash, fmt.Errorf("consumed_queue_entries length must match consumed_queue_messages")
	}
	if len(request.ConsumedQueueEntries) == 0 {
		return new(big.Int), new(big.Int), new(big.Int), messageID, messageHash, nil
	}

	entry := request.ConsumedQueueEntries[0]
	if entry.MessageKind != 1 && entry.MessageKind != 2 {
		return nil, nil, nil, messageID, messageHash, fmt.Errorf("consumed_queue_entries[0].message_kind must be 1 or 2")
	}

	queueIndex, err := parseUintAsField(entry.QueueIndex, "consumed_queue_entries[0].queue_index")
	if err != nil {
		return nil, nil, nil, messageID, messageHash, err
	}
	messageKind, err := parseUintAsField(uint64(entry.MessageKind), "consumed_queue_entries[0].message_kind")
	if err != nil {
		return nil, nil, nil, messageID, messageHash, err
	}
	messageID, err = parseUint256LittleEndianBytes(entry.MessageID, "consumed_queue_entries[0].message_id")
	if err != nil {
		return nil, nil, nil, messageID, messageHash, err
	}
	messageHash, err = parseUint256LittleEndianBytes(entry.MessageHash, "consumed_queue_entries[0].message_hash")
	if err != nil {
		return nil, nil, nil, messageID, messageHash, err
	}

	return new(big.Int).SetUint64(1), queueIndex, messageKind, messageID, messageHash, nil
}

func newPoseidonHasher(api frontend.API) (gnarkhash.FieldHasher, error) {
	perm, err := poseidon2circuit.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return nil, err
	}
	return gnarkhash.NewMerkleDamgardHasher(api, perm, 0), nil
}

func poseidonHash(inputs ...*big.Int) (*big.Int, error) {
	perm := poseidon2native.NewPermutation(2, 6, 50)
	state := make([]byte, bls12381fr.Bytes)
	for _, input := range inputs {
		var encoded bls12381fr.Element
		encoded.SetBigInt(input)
		var err error
		state, err = perm.Compress(state, encoded.Marshal())
		if err != nil {
			return nil, err
		}
	}
	var out bls12381fr.Element
	if err := out.SetBytesCanonical(state); err != nil {
		return nil, err
	}
	return out.BigInt(new(big.Int)), nil
}

func parseFieldHex(raw string, fieldName string) (*big.Int, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is required", fieldName)
	}
	value, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return nil, fmt.Errorf("%s is not valid hex", fieldName)
	}
	if value.Cmp(bls12381fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("%s does not fit BLS12-381 scalar field", fieldName)
	}
	return value, nil
}

func parseUint256LittleEndianBytes(raw string, fieldName string) ([32]uints.U8, error) {
	var out [32]uints.U8
	if raw == "" {
		return out, fmt.Errorf("%s is required", fieldName)
	}
	normalized := raw
	if len(normalized) > 64 {
		return out, fmt.Errorf("%s is longer than 32 bytes", fieldName)
	}
	for len(normalized) < 64 {
		normalized = "0" + normalized
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return out, fmt.Errorf("%s is not valid hex", fieldName)
	}
	for i := 0; i < len(decoded); i++ {
		out[i] = uints.NewU8(decoded[len(decoded)-1-i])
	}
	return out, nil
}

func parseUintAsField(value uint64, fieldName string) (*big.Int, error) {
	out := new(big.Int).SetUint64(value)
	if out.Cmp(bls12381fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("%s does not fit BLS12-381 scalar field", fieldName)
	}
	return out, nil
}

func formatFieldHex(value *big.Int) string {
	return value.Text(16)
}

func normalizeHex(value string) string {
	normalized := value
	for len(normalized) > 1 && normalized[0] == '0' {
		normalized = normalized[1:]
	}
	if normalized == "" {
		return "0"
	}
	return normalized
}

func decodeDataChunks(chunksHex []string) ([][]byte, error) {
	chunks := make([][]byte, 0, len(chunksHex))
	for i, chunkHex := range chunksHex {
		chunk, err := hex.DecodeString(chunkHex)
		if err != nil {
			return nil, fmt.Errorf("data_chunks_hex[%d] is not valid hex", i)
		}
		if len(chunk) == 0 {
			return nil, fmt.Errorf("data_chunks_hex[%d] decoded to an empty chunk", i)
		}
		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

func computePublishedDataSize(chunks [][]byte) uint64 {
	var total uint64
	for _, chunk := range chunks {
		total += uint64(len(chunk))
	}
	return total
}

func computePublishedDataRoot(chunks [][]byte) string {
	payload := make([]byte, 0, 6+4+(len(chunks)*4))
	payload = append(payload, []byte{'V', 'S', 'C', 'R', 0x01}...)
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(chunks)))
	payload = append(payload, count[:]...)
	for _, chunk := range chunks {
		var chunkLen [4]byte
		binary.LittleEndian.PutUint32(chunkLen[:], uint32(len(chunk)))
		payload = append(payload, chunkLen[:]...)
		payload = append(payload, chunk...)
	}
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	reversed := make([]byte, len(second))
	for i := range second {
		reversed[i] = second[len(second)-1-i]
	}
	return hex.EncodeToString(reversed)
}
