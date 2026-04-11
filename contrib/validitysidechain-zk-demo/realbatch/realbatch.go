package realbatch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

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
const FinalProfileName = "groth16_bls12_381_poseidon_v2"
const ExperimentalPublicInputVersion uint8 = 2
const FinalPublicInputVersion uint8 = 5

var queueConsumeMagic = []uint8{'V', 'S', 'C', 'Q', 'C', 0x01}
var queuePrefixCommitmentMagic = []uint8{'V', 'S', 'C', 'Q', 'P', 0x01}
var withdrawalRootMagic = []uint8{'V', 'S', 'C', 'W', 0x01}
var withdrawalLeafMagic = []uint8{'V', 'S', 'C', 'W', 0x02}
var withdrawalNodeMagic = []uint8{'V', 'S', 'C', 'W', 0x03}

func IsSupportedProfileName(profileName string) bool {
	return profileName == ProfileName || profileName == FinalProfileName
}

func PublicInputVersionForProfileName(profileName string) (uint8, error) {
	switch profileName {
	case ProfileName:
		return ExperimentalPublicInputVersion, nil
	case FinalProfileName:
		return FinalPublicInputVersion, nil
	default:
		return 0, fmt.Errorf("unsupported profile name %q", profileName)
	}
}

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

	WithdrawalLeafPresent               frontend.Variable
	WithdrawalLeafID                    [32]uints.U8
	WithdrawalLeafAmount                frontend.Variable
	WithdrawalLeafDestinationCommitment [32]uints.U8
}

type PoseidonBatchTransitionCircuitDecomposedPublicInputs struct {
	SidechainID             frontend.Variable `gnark:",public"`
	BatchNumber             frontend.Variable `gnark:",public"`
	PriorStateRoot          frontend.Variable `gnark:",public"`
	NewStateRoot            frontend.Variable `gnark:",public"`
	L1MessageRootBeforeLo   frontend.Variable `gnark:",public"`
	L1MessageRootBeforeHi   frontend.Variable `gnark:",public"`
	L1MessageRootAfterLo    frontend.Variable `gnark:",public"`
	L1MessageRootAfterHi    frontend.Variable `gnark:",public"`
	ConsumedQueueMessages   frontend.Variable `gnark:",public"`
	QueuePrefixCommitmentLo frontend.Variable `gnark:",public"`
	QueuePrefixCommitmentHi frontend.Variable `gnark:",public"`
	WithdrawalRootLo        frontend.Variable `gnark:",public"`
	WithdrawalRootHi        frontend.Variable `gnark:",public"`
	DataRootLo              frontend.Variable `gnark:",public"`
	DataRootHi              frontend.Variable `gnark:",public"`
	DataSize                frontend.Variable `gnark:",public"`
}

func (c *PoseidonBatchTransitionCircuit) Define(api frontend.API) error {
	// Keep the experimental native profile on the fixed 11 public inputs for now.
	// Wiring the SHA-based queue/withdrawal witness gadgets directly into Define
	// currently makes gnark emit an extra commitment/public-input wire, which
	// breaks the node's native verifier artifact layout.
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
		c.WithdrawalRoot,
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
	return nil
}

func (c *PoseidonBatchTransitionCircuitDecomposedPublicInputs) Define(api frontend.API) error {
	transitionHasher, err := newPoseidonHasher(api)
	if err != nil {
		return err
	}
	transitionHasher.Write(
		c.SidechainID,
		c.BatchNumber,
		c.PriorStateRoot,
		c.L1MessageRootBeforeLo,
		c.L1MessageRootBeforeHi,
		c.L1MessageRootAfterLo,
		c.L1MessageRootAfterHi,
		c.ConsumedQueueMessages,
		c.QueuePrefixCommitmentLo,
		c.QueuePrefixCommitmentHi,
		c.WithdrawalRootLo,
		c.WithdrawalRootHi,
		c.DataRootLo,
		c.DataRootHi,
		c.DataSize,
	)
	transitionCommitment := transitionHasher.Sum()

	stateHasher, err := newPoseidonHasher(api)
	if err != nil {
		return err
	}
	stateHasher.Write(c.PriorStateRoot, transitionCommitment)
	api.AssertIsEqual(c.NewStateRoot, stateHasher.Sum())
	return nil
}

func NewCircuit(profileName string) (frontend.Circuit, error) {
	switch profileName {
	case ProfileName:
		return &PoseidonBatchTransitionCircuit{}, nil
	case FinalProfileName:
		return &PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, nil
	default:
		return nil, fmt.Errorf("unsupported profile name %q", profileName)
	}
}

func BuildAssignment(request toybatch.CommandRequest) (frontend.Circuit, error) {
	switch request.ProfileName {
	case ProfileName:
		if err := validatePublishedDataWitness(request); err != nil {
			return nil, err
		}
		assignment, err := buildExperimentalAssignment(request)
		if err != nil {
			return nil, err
		}
		return &assignment, nil
	case FinalProfileName:
		if err := ValidateDerivedRequest(request); err != nil {
			return nil, err
		}
		assignment, err := buildDecomposedPublicAssignment(request)
		if err != nil {
			return nil, err
		}
		return &assignment, nil
	default:
		return nil, fmt.Errorf("unsupported profile name %q", request.ProfileName)
	}
}

func BuildPublicAssignment(request toybatch.CommandRequest) (frontend.Circuit, error) {
	switch request.ProfileName {
	case ProfileName:
		assignment, err := buildExperimentalPublicAssignment(request)
		if err != nil {
			return nil, err
		}
		return &assignment, nil
	case FinalProfileName:
		assignment, err := buildDecomposedPublicAssignment(request)
		if err != nil {
			return nil, err
		}
		return &assignment, nil
	default:
		return nil, fmt.Errorf("unsupported profile name %q", request.ProfileName)
	}
}

func profileUsesExperimentalSingleEntryWitnesses(profileName string) bool {
	return profileName == ProfileName
}

func requiresCanonicalCurrentChainstateBinding(profileName string) bool {
	return profileName == FinalProfileName
}

func requiresExplicitCanonicalWitnessVectors(profileName string) bool {
	return profileName == FinalProfileName
}

func buildExperimentalAssignment(request toybatch.CommandRequest) (PoseidonBatchTransitionCircuit, error) {
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
	withdrawalLeafPresent, withdrawalLeafID, withdrawalLeafAmount, withdrawalLeafDestinationCommitment, err :=
		buildWithdrawalWitness(request)
	if err != nil {
		return PoseidonBatchTransitionCircuit{}, err
	}

	return PoseidonBatchTransitionCircuit{
		SidechainID:                         sidechainID,
		BatchNumber:                         batchNumber,
		PriorStateRoot:                      priorStateRoot,
		NewStateRoot:                        newStateRoot,
		L1MessageRootBefore:                 l1MessageRootBefore,
		L1MessageRootAfter:                  l1MessageRootAfter,
		ConsumedQueueMessages:               consumedQueueMessages,
		QueuePrefixCommitment:               queuePrefixCommitment,
		WithdrawalRoot:                      withdrawalRoot,
		DataRoot:                            dataRoot,
		DataSize:                            dataSize,
		ConsumedEntryPresent:                consumedEntryPresent,
		ConsumedEntryQueueIndex:             consumedEntryQueueIndex,
		ConsumedEntryMessageKind:            consumedEntryMessageKind,
		ConsumedEntryMessageID:              consumedEntryMessageID,
		ConsumedEntryMessageHash:            consumedEntryMessageHash,
		WithdrawalLeafPresent:               withdrawalLeafPresent,
		WithdrawalLeafID:                    withdrawalLeafID,
		WithdrawalLeafAmount:                withdrawalLeafAmount,
		WithdrawalLeafDestinationCommitment: withdrawalLeafDestinationCommitment,
	}, nil
}

func buildExperimentalPublicAssignment(request toybatch.CommandRequest) (PoseidonBatchTransitionCircuit, error) {
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

	return PoseidonBatchTransitionCircuit{
		SidechainID:           sidechainID,
		BatchNumber:           batchNumber,
		PriorStateRoot:        priorStateRoot,
		NewStateRoot:          newStateRoot,
		L1MessageRootBefore:   l1MessageRootBefore,
		L1MessageRootAfter:    l1MessageRootAfter,
		ConsumedQueueMessages: consumedQueueMessages,
		QueuePrefixCommitment: queuePrefixCommitment,
		WithdrawalRoot:        withdrawalRoot,
		DataRoot:              dataRoot,
		DataSize:              dataSize,
	}, nil
}

func buildDecomposedPublicAssignment(request toybatch.CommandRequest) (PoseidonBatchTransitionCircuitDecomposedPublicInputs, error) {
	sidechainID, err := parseUintAsField(request.SidechainID, "sidechain_id")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	batchNumber, err := parseUintAsField(uint64(request.PublicInputs.BatchNumber), "batch_number")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	priorStateRoot, err := parseFieldHex(request.PublicInputs.PriorStateRoot, "prior_state_root")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	newStateRoot, err := parseFieldHex(request.PublicInputs.NewStateRoot, "new_state_root")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	l1MessageRootBeforeLo, l1MessageRootBeforeHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.L1MessageRootBefore, "l1_message_root_before")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	l1MessageRootAfterLo, l1MessageRootAfterHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.L1MessageRootAfter, "l1_message_root_after")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	consumedQueueMessages, err := parseUintAsField(uint64(request.PublicInputs.ConsumedQueueMessages), "consumed_queue_messages")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	queuePrefixCommitmentLo, queuePrefixCommitmentHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.QueuePrefixCommitment, "queue_prefix_commitment")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	withdrawalRootLo, withdrawalRootHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.WithdrawalRoot, "withdrawal_root")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	dataRootLo, dataRootHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.DataRoot, "data_root")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}
	dataSize, err := parseUintAsField(uint64(request.PublicInputs.DataSize), "data_size")
	if err != nil {
		return PoseidonBatchTransitionCircuitDecomposedPublicInputs{}, err
	}

	return PoseidonBatchTransitionCircuitDecomposedPublicInputs{
		SidechainID:             sidechainID,
		BatchNumber:             batchNumber,
		PriorStateRoot:          priorStateRoot,
		NewStateRoot:            newStateRoot,
		L1MessageRootBeforeLo:   l1MessageRootBeforeLo,
		L1MessageRootBeforeHi:   l1MessageRootBeforeHi,
		L1MessageRootAfterLo:    l1MessageRootAfterLo,
		L1MessageRootAfterHi:    l1MessageRootAfterHi,
		ConsumedQueueMessages:   consumedQueueMessages,
		QueuePrefixCommitmentLo: queuePrefixCommitmentLo,
		QueuePrefixCommitmentHi: queuePrefixCommitmentHi,
		WithdrawalRootLo:        withdrawalRootLo,
		WithdrawalRootHi:        withdrawalRootHi,
		DataRootLo:              dataRootLo,
		DataRootHi:              dataRootHi,
		DataSize:                dataSize,
	}, nil
}

func ManifestPublicInputs(publicInputVersion uint8) ([]string, error) {
	switch publicInputVersion {
	case ExperimentalPublicInputVersion:
		return []string{
			"sidechain_id",
			"batch_number",
			"prior_state_root",
			"new_state_root",
			"l1_message_root_before",
			"l1_message_root_after",
			"consumed_queue_messages",
			"queue_prefix_commitment",
			"withdrawal_root",
			"data_root",
			"data_size",
		}, nil
	case FinalPublicInputVersion:
		return []string{
			"sidechain_id",
			"batch_number",
			"prior_state_root",
			"new_state_root",
			"l1_message_root_before_lo",
			"l1_message_root_before_hi",
			"l1_message_root_after_lo",
			"l1_message_root_after_hi",
			"consumed_queue_messages",
			"queue_prefix_commitment_lo",
			"queue_prefix_commitment_hi",
			"withdrawal_root_lo",
			"withdrawal_root_hi",
			"data_root_lo",
			"data_root_hi",
			"data_size",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public_input_version %d", publicInputVersion)
	}
}

func PublicInputsMap(request toybatch.CommandRequest, publicInputVersion uint8) (map[string]string, error) {
	inputNames, err := ManifestPublicInputs(publicInputVersion)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(inputNames))
	for _, inputName := range inputNames {
		value, err := publicInputValue(request, inputName)
		if err != nil {
			return nil, err
		}
		out[inputName] = value
	}
	return out, nil
}

func publicInputValue(request toybatch.CommandRequest, inputName string) (string, error) {
	switch inputName {
	case "sidechain_id":
		return strconv.FormatUint(uint64(request.SidechainID), 10), nil
	case "batch_number":
		return strconv.FormatUint(uint64(request.PublicInputs.BatchNumber), 10), nil
	case "consumed_queue_messages":
		return strconv.FormatUint(uint64(request.PublicInputs.ConsumedQueueMessages), 10), nil
	case "data_size":
		return strconv.FormatUint(uint64(request.PublicInputs.DataSize), 10), nil
	}

	if value, ok := appendUint256ManifestValue(inputName, "prior_state_root", request.PublicInputs.PriorStateRoot); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "new_state_root", request.PublicInputs.NewStateRoot); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "l1_message_root_before", request.PublicInputs.L1MessageRootBefore); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "l1_message_root_after", request.PublicInputs.L1MessageRootAfter); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "queue_prefix_commitment", request.PublicInputs.QueuePrefixCommitment); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "withdrawal_root", request.PublicInputs.WithdrawalRoot); ok {
		return value, nil
	}
	if value, ok := appendUint256ManifestValue(inputName, "data_root", request.PublicInputs.DataRoot); ok {
		return value, nil
	}

	return "", fmt.Errorf("unsupported public input name %q", inputName)
}

func appendUint256ManifestValue(inputName string, baseName string, raw string) (string, bool) {
	normalized := normalizeUint256Hex(raw)
	if inputName == baseName {
		return normalized, true
	}
	if inputName == baseName+"_lo" {
		low, _ := decomposeUint256HexTo128BitLimbs(normalized)
		return low, true
	}
	if inputName == baseName+"_hi" {
		_, high := decomposeUint256HexTo128BitLimbs(normalized)
		return high, true
	}
	return "", false
}

func normalizeUint256Hex(raw string) string {
	normalized := normalizeHex(raw)
	if normalized == "0" {
		return normalized
	}
	if len(normalized) > 64 {
		panic("uint256 hex longer than 32 bytes")
	}
	return normalized
}

func decomposeUint256HexTo128BitLimbs(raw string) (string, string) {
	normalized := raw
	if normalized == "" {
		normalized = "0"
	}
	for len(normalized) < 64 {
		normalized = "0" + normalized
	}
	if len(normalized) > 64 {
		panic("uint256 hex longer than 32 bytes")
	}

	high := normalizeHex(normalized[:32])
	low := normalizeHex(normalized[32:])
	return low, high
}

func parseUint256HexTo128BitLimbs(raw string, fieldName string) (*big.Int, *big.Int, error) {
	lowHex, highHex := decomposeUint256HexTo128BitLimbs(normalizeUint256Hex(raw))
	low, err := parseFieldHex(lowHex, fieldName+"_lo")
	if err != nil {
		return nil, nil, err
	}
	high, err := parseFieldHex(highHex, fieldName+"_hi")
	if err != nil {
		return nil, nil, err
	}
	return low, high, nil
}

func DeriveRequest(request toybatch.CommandRequest) (toybatch.CommandRequest, error) {
	publicInputVersion, err := PublicInputVersionForProfileName(request.ProfileName)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}

	derivedQueueRootAfter, derivedQueuePrefixCommitment, err := computeQueueBindingsForProfile(request)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	dataChunks, err := decodeDataChunks(request.DataChunksHex)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	derivedDataRoot := computePublishedDataRoot(dataChunks)
	derivedDataSize := uint32(computePublishedDataSize(dataChunks))

	cleared := ensureDerivedTargetsCleared(request)
	cleared.PublicInputs.L1MessageRootAfter = derivedQueueRootAfter
	cleared.PublicInputs.QueuePrefixCommitment = derivedQueuePrefixCommitment
	cleared.PublicInputs.DataRoot = derivedDataRoot
	cleared.PublicInputs.DataSize = derivedDataSize
	withdrawalRoot, err := computeWithdrawalRootForProfile(request)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	cleared.PublicInputs.WithdrawalRoot = withdrawalRoot
	transitionCommitment, err := computeTransitionCommitment(cleared, publicInputVersion)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	priorStateRoot, err := parseFieldHex(cleared.PublicInputs.PriorStateRoot, "prior_state_root")
	if err != nil {
		return toybatch.CommandRequest{}, err
	}
	newStateRoot, err := poseidonHash(priorStateRoot, transitionCommitment)
	if err != nil {
		return toybatch.CommandRequest{}, err
	}

	derived := request
	derived.PublicInputs.L1MessageRootAfter = derivedQueueRootAfter
	derived.PublicInputs.QueuePrefixCommitment = derivedQueuePrefixCommitment
	derived.PublicInputs.DataRoot = derivedDataRoot
	derived.PublicInputs.DataSize = derivedDataSize
	derived.PublicInputs.NewStateRoot = formatFieldHex(newStateRoot)
	derived.PublicInputs.WithdrawalRoot = withdrawalRoot
	return derived, nil
}

func ValidateProofRequestContract(request toybatch.CommandRequest) error {
	if requiresCanonicalCurrentChainstateBinding(request.ProfileName) {
		if strings.TrimSpace(request.CurrentStateRoot) == "" {
			return fmt.Errorf("current_state_root is required for canonical v2 proof requests")
		}
		if strings.TrimSpace(request.CurrentWithdrawalRoot) == "" {
			return fmt.Errorf("current_withdrawal_root is required for canonical v2 proof requests")
		}
		if strings.TrimSpace(request.CurrentDataRoot) == "" {
			return fmt.Errorf("current_data_root is required for canonical v2 proof requests")
		}
		if strings.TrimSpace(request.CurrentL1MessageRoot) == "" {
			return fmt.Errorf("current_l1_message_root is required for canonical v2 proof requests")
		}
	}
	if requiresExplicitCanonicalWitnessVectors(request.ProfileName) {
		if request.ConsumedQueueEntries == nil {
			return fmt.Errorf("consumed_queue_entries must be provided explicitly for canonical v2 proof requests")
		}
		if request.WithdrawalLeaves == nil {
			return fmt.Errorf("withdrawal_leaves must be provided explicitly for canonical v2 proof requests")
		}
		if request.DataChunksHex == nil {
			return fmt.Errorf("data_chunks_hex must be provided explicitly for canonical v2 proof requests")
		}
	}
	if err := validateCurrentChainstateBinding(request); err != nil {
		return err
	}
	return nil
}

func ValidateDerivedRequest(request toybatch.CommandRequest) error {
	if err := ValidateProofRequestContract(request); err != nil {
		return err
	}
	derived, err := DeriveRequest(request)
	if err != nil {
		return err
	}
	if err := validatePublishedDataWitness(request); err != nil {
		return err
	}
	if err := validateQueueWitnessForProfile(request); err != nil {
		return err
	}
	if err := validateWithdrawalWitnessForProfile(request); err != nil {
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

func validateCurrentChainstateBinding(request toybatch.CommandRequest) error {
	if request.CurrentStateRoot != "" &&
		normalizeHex(request.PublicInputs.PriorStateRoot) != normalizeHex(request.CurrentStateRoot) {
		return fmt.Errorf("prior_state_root does not match current_state_root")
	}
	if request.CurrentL1MessageRoot != "" &&
		normalizeHex(request.PublicInputs.L1MessageRootBefore) != normalizeHex(request.CurrentL1MessageRoot) {
		return fmt.Errorf("l1_message_root_before does not match current_l1_message_root")
	}
	if request.RequireWithdrawalWitnessOnRootChange &&
		!request.WithdrawalLeavesSupplied &&
		len(request.WithdrawalLeaves) == 0 &&
		request.CurrentWithdrawalRoot != "" &&
		normalizeHex(request.PublicInputs.WithdrawalRoot) != normalizeHex(request.CurrentWithdrawalRoot) {
		return fmt.Errorf("withdrawal_root changes require withdrawal_leaves witness under current witness policy")
	}
	return nil
}

func validateQueueWitnessForProfile(request toybatch.CommandRequest) error {
	if profileUsesExperimentalSingleEntryWitnesses(request.ProfileName) {
		return validateExperimentalQueueWitness(request)
	}
	return validateGenericQueueWitness(request)
}

func validateWithdrawalWitnessForProfile(request toybatch.CommandRequest) error {
	if profileUsesExperimentalSingleEntryWitnesses(request.ProfileName) {
		return validateExperimentalWithdrawalWitness(request)
	}
	return validateGenericWithdrawalWitness(request)
}

func validatePublishedDataWitness(request toybatch.CommandRequest) error {
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

func validateExperimentalQueueWitness(request toybatch.CommandRequest) error {
	if len(request.ConsumedQueueEntries) > 1 {
		return fmt.Errorf("experimental real profile supports at most one consumed queue entry")
	}
	if len(request.ConsumedQueueEntries) != int(request.PublicInputs.ConsumedQueueMessages) {
		return fmt.Errorf("consumed_queue_entries length must match consumed_queue_messages")
	}
	if len(request.ConsumedQueueEntries) == 0 {
		if normalizeHex(request.PublicInputs.L1MessageRootAfter) != normalizeHex(request.PublicInputs.L1MessageRootBefore) {
			return fmt.Errorf("l1_message_root_after does not match the empty consumed queue witness")
		}
		if normalizeHex(request.PublicInputs.QueuePrefixCommitment) != "0" {
			return fmt.Errorf("queue_prefix_commitment does not match the empty consumed queue witness")
		}
		return nil
	}

	entry := request.ConsumedQueueEntries[0]
	if entry.MessageKind != 1 && entry.MessageKind != 2 {
		return fmt.Errorf("consumed_queue_entries[0].message_kind must be 1 or 2")
	}
	expectedAfter := computeQueueStepDisplayHex(
		queueConsumeMagic,
		uint8(request.SidechainID),
		request.PublicInputs.L1MessageRootBefore,
		entry,
	)
	if normalizeHex(request.PublicInputs.L1MessageRootAfter) != normalizeHex(expectedAfter) {
		return fmt.Errorf("l1_message_root_after does not match consumed_queue_entries witness")
	}
	expectedPrefix := computeQueueStepDisplayHex(
		queuePrefixCommitmentMagic,
		uint8(request.SidechainID),
		"0",
		entry,
	)
	if normalizeHex(request.PublicInputs.QueuePrefixCommitment) != normalizeHex(expectedPrefix) {
		return fmt.Errorf("queue_prefix_commitment does not match consumed_queue_entries witness")
	}
	return nil
}

func validateGenericQueueWitness(request toybatch.CommandRequest) error {
	if len(request.ConsumedQueueEntries) != int(request.PublicInputs.ConsumedQueueMessages) {
		return fmt.Errorf("consumed_queue_entries length must match consumed_queue_messages")
	}

	expectedAfter := normalizeHex(request.PublicInputs.L1MessageRootBefore)
	expectedPrefix := "0"
	for index, entry := range request.ConsumedQueueEntries {
		if entry.MessageKind != 1 && entry.MessageKind != 2 {
			return fmt.Errorf("consumed_queue_entries[%d].message_kind must be 1 or 2", index)
		}
		expectedAfter = computeQueueStepDisplayHex(
			queueConsumeMagic,
			uint8(request.SidechainID),
			expectedAfter,
			entry,
		)
		expectedPrefix = computeQueueStepDisplayHex(
			queuePrefixCommitmentMagic,
			uint8(request.SidechainID),
			expectedPrefix,
			entry,
		)
	}

	if normalizeHex(request.PublicInputs.L1MessageRootAfter) != normalizeHex(expectedAfter) {
		return fmt.Errorf("l1_message_root_after does not match consumed_queue_entries witness")
	}
	if normalizeHex(request.PublicInputs.QueuePrefixCommitment) != normalizeHex(expectedPrefix) {
		return fmt.Errorf("queue_prefix_commitment does not match consumed_queue_entries witness")
	}
	return nil
}

func validateExperimentalWithdrawalWitness(request toybatch.CommandRequest) error {
	expectedRoot, err := computeExperimentalWithdrawalRootFromRequest(request)
	if err != nil {
		return err
	}
	if normalizeHex(request.PublicInputs.WithdrawalRoot) != normalizeHex(expectedRoot) {
		return fmt.Errorf("withdrawal_root does not match withdrawal_leaves witness")
	}
	return nil
}

func validateGenericWithdrawalWitness(request toybatch.CommandRequest) error {
	expectedRoot, err := computeGenericWithdrawalRootFromRequest(request)
	if err != nil {
		return err
	}
	if normalizeHex(request.PublicInputs.WithdrawalRoot) != normalizeHex(expectedRoot) {
		return fmt.Errorf("withdrawal_root does not match withdrawal_leaves witness")
	}
	return nil
}

func ensureDerivedTargetsCleared(request toybatch.CommandRequest) toybatch.CommandRequest {
	request.PublicInputs.L1MessageRootAfter = "0"
	request.PublicInputs.QueuePrefixCommitment = "0"
	request.PublicInputs.NewStateRoot = "0"
	request.PublicInputs.WithdrawalRoot = "0"
	request.PublicInputs.DataRoot = "0"
	request.PublicInputs.DataSize = 0
	return request
}

func computeQueueBindingsForProfile(request toybatch.CommandRequest) (string, string, error) {
	if profileUsesExperimentalSingleEntryWitnesses(request.ProfileName) {
		return computeExperimentalQueueBindings(request)
	}
	return computeGenericQueueBindings(request)
}

func computeExperimentalQueueBindings(request toybatch.CommandRequest) (string, string, error) {
	if len(request.ConsumedQueueEntries) > 1 {
		return "", "", fmt.Errorf("experimental real profile supports at most one consumed queue entry")
	}
	if len(request.ConsumedQueueEntries) != int(request.PublicInputs.ConsumedQueueMessages) {
		return "", "", fmt.Errorf("consumed_queue_entries length must match consumed_queue_messages")
	}
	if len(request.ConsumedQueueEntries) == 0 {
		return normalizeHex(request.PublicInputs.L1MessageRootBefore), "0", nil
	}

	entry := request.ConsumedQueueEntries[0]
	if entry.MessageKind != 1 && entry.MessageKind != 2 {
		return "", "", fmt.Errorf("consumed_queue_entries[0].message_kind must be 1 or 2")
	}
	expectedAfter := computeQueueStepDisplayHex(
		queueConsumeMagic,
		uint8(request.SidechainID),
		request.PublicInputs.L1MessageRootBefore,
		entry,
	)
	expectedPrefix := computeQueueStepDisplayHex(
		queuePrefixCommitmentMagic,
		uint8(request.SidechainID),
		"0",
		entry,
	)
	return expectedAfter, expectedPrefix, nil
}

func computeGenericQueueBindings(request toybatch.CommandRequest) (string, string, error) {
	if len(request.ConsumedQueueEntries) != int(request.PublicInputs.ConsumedQueueMessages) {
		return "", "", fmt.Errorf("consumed_queue_entries length must match consumed_queue_messages")
	}

	expectedAfter := normalizeHex(request.PublicInputs.L1MessageRootBefore)
	expectedPrefix := "0"
	for index, entry := range request.ConsumedQueueEntries {
		if entry.MessageKind != 1 && entry.MessageKind != 2 {
			return "", "", fmt.Errorf("consumed_queue_entries[%d].message_kind must be 1 or 2", index)
		}
		expectedAfter = computeQueueStepDisplayHex(
			queueConsumeMagic,
			uint8(request.SidechainID),
			expectedAfter,
			entry,
		)
		expectedPrefix = computeQueueStepDisplayHex(
			queuePrefixCommitmentMagic,
			uint8(request.SidechainID),
			expectedPrefix,
			entry,
		)
	}

	return expectedAfter, expectedPrefix, nil
}

func computeTransitionCommitment(request toybatch.CommandRequest, publicInputVersion uint8) (*big.Int, error) {
	sidechainID, err := parseUintAsField(request.SidechainID, "sidechain_id")
	if err != nil {
		return nil, err
	}
	batchNumber, err := parseUintAsField(uint64(request.PublicInputs.BatchNumber), "batch_number")
	if err != nil {
		return nil, err
	}
	priorStateRoot, err := parseFieldHex(request.PublicInputs.PriorStateRoot, "prior_state_root")
	if err != nil {
		return nil, err
	}
	consumedQueueMessages, err := parseUintAsField(uint64(request.PublicInputs.ConsumedQueueMessages), "consumed_queue_messages")
	if err != nil {
		return nil, err
	}
	dataSize, err := parseUintAsField(uint64(request.PublicInputs.DataSize), "data_size")
	if err != nil {
		return nil, err
	}

	switch publicInputVersion {
	case ExperimentalPublicInputVersion:
		l1MessageRootBefore, err := parseFieldHex(request.PublicInputs.L1MessageRootBefore, "l1_message_root_before")
		if err != nil {
			return nil, err
		}
		l1MessageRootAfter, err := parseFieldHex(request.PublicInputs.L1MessageRootAfter, "l1_message_root_after")
		if err != nil {
			return nil, err
		}
		queuePrefixCommitment, err := parseFieldHex(request.PublicInputs.QueuePrefixCommitment, "queue_prefix_commitment")
		if err != nil {
			return nil, err
		}
		withdrawalRoot, err := parseFieldHex(request.PublicInputs.WithdrawalRoot, "withdrawal_root")
		if err != nil {
			return nil, err
		}
		dataRoot, err := parseFieldHex(request.PublicInputs.DataRoot, "data_root")
		if err != nil {
			return nil, err
		}
		return poseidonHash(
			sidechainID,
			batchNumber,
			priorStateRoot,
			l1MessageRootBefore,
			l1MessageRootAfter,
			consumedQueueMessages,
			queuePrefixCommitment,
			withdrawalRoot,
			dataRoot,
			dataSize,
		)
	case FinalPublicInputVersion:
		l1MessageRootBeforeLo, l1MessageRootBeforeHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.L1MessageRootBefore, "l1_message_root_before")
		if err != nil {
			return nil, err
		}
		l1MessageRootAfterLo, l1MessageRootAfterHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.L1MessageRootAfter, "l1_message_root_after")
		if err != nil {
			return nil, err
		}
		queuePrefixCommitmentLo, queuePrefixCommitmentHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.QueuePrefixCommitment, "queue_prefix_commitment")
		if err != nil {
			return nil, err
		}
		withdrawalRootLo, withdrawalRootHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.WithdrawalRoot, "withdrawal_root")
		if err != nil {
			return nil, err
		}
		dataRootLo, dataRootHi, err := parseUint256HexTo128BitLimbs(request.PublicInputs.DataRoot, "data_root")
		if err != nil {
			return nil, err
		}
		return poseidonHash(
			sidechainID,
			batchNumber,
			priorStateRoot,
			l1MessageRootBeforeLo,
			l1MessageRootBeforeHi,
			l1MessageRootAfterLo,
			l1MessageRootAfterHi,
			consumedQueueMessages,
			queuePrefixCommitmentLo,
			queuePrefixCommitmentHi,
			withdrawalRootLo,
			withdrawalRootHi,
			dataRootLo,
			dataRootHi,
			dataSize,
		)
	default:
		return nil, fmt.Errorf("unsupported public_input_version %d", publicInputVersion)
	}
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

func assertExperimentalWithdrawalWitness(api frontend.API, circuit *PoseidonBatchTransitionCircuit) error {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	u64api, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	api.AssertIsBoolean(circuit.WithdrawalLeafPresent)
	withdrawalRoot := fieldToLittleEndianBytes(api, bapi, circuit.WithdrawalRoot)
	zeroRoot := zeroByteArray32()

	leafPreimage := make([]uints.U8, 0, len(withdrawalLeafMagic)+32+8+32)
	leafPreimage = append(leafPreimage, uints.NewU8Array(withdrawalLeafMagic)...)
	leafPreimage = append(leafPreimage, circuit.WithdrawalLeafID[:]...)
	leafPreimage = append(leafPreimage, u64api.UnpackLSB(u64api.ValueOf(circuit.WithdrawalLeafAmount))...)
	leafPreimage = append(leafPreimage, circuit.WithdrawalLeafDestinationCommitment[:]...)
	leafHash, err := doubleSHA256(api, leafPreimage)
	if err != nil {
		return err
	}

	leafCount := api.Select(circuit.WithdrawalLeafPresent, 1, 0)
	selectedMerkleRoot := selectByteArray32(bapi, circuit.WithdrawalLeafPresent, leafHash, zeroRoot)
	rootPreimage := make([]uints.U8, 0, len(withdrawalRootMagic)+4+32)
	rootPreimage = append(rootPreimage, uints.NewU8Array(withdrawalRootMagic)...)
	rootPreimage = append(rootPreimage, packUint32LittleEndian(api, bapi, leafCount)...)
	rootPreimage = append(rootPreimage, selectedMerkleRoot[:]...)
	expectedRoot, err := doubleSHA256(api, rootPreimage)
	if err != nil {
		return err
	}

	assertByteArray32Equal(bapi, expectedRoot, withdrawalRoot)
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

func packUint32LittleEndian(api frontend.API, bapi *uints.Bytes, value frontend.Variable) []uints.U8 {
	encoded := make([]uints.U8, 4)
	bitsLE := bits.ToBinary(api, value, bits.WithNbDigits(32))
	for i := 0; i < 4; i++ {
		encoded[i] = bapi.ValueOf(bits.FromBinary(api, bitsLE[i*8:(i+1)*8]))
	}
	return encoded
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

func buildWithdrawalWitness(request toybatch.CommandRequest) (frontend.Variable, [32]uints.U8, frontend.Variable, [32]uints.U8, error) {
	var withdrawalID [32]uints.U8
	var destinationCommitment [32]uints.U8

	if len(request.WithdrawalLeaves) > 1 {
		return nil, withdrawalID, nil, destinationCommitment, fmt.Errorf("experimental real profile supports at most one withdrawal leaf")
	}
	if len(request.WithdrawalLeaves) == 0 {
		return new(big.Int), withdrawalID, new(big.Int), destinationCommitment, nil
	}

	leaf := request.WithdrawalLeaves[0]
	withdrawalID, err := parseUint256LittleEndianBytes(leaf.WithdrawalID, "withdrawal_leaves[0].withdrawal_id")
	if err != nil {
		return nil, withdrawalID, nil, destinationCommitment, err
	}
	destinationCommitment, err = parseUint256LittleEndianBytes(
		leaf.DestinationCommitment,
		"withdrawal_leaves[0].destination_commitment")
	if err != nil {
		return nil, withdrawalID, nil, destinationCommitment, err
	}
	amount, err := parseAmountSatsField(leaf.Amount, "withdrawal_leaves[0].amount")
	if err != nil {
		return nil, withdrawalID, nil, destinationCommitment, err
	}

	return new(big.Int).SetUint64(1), withdrawalID, amount, destinationCommitment, nil
}

func computeWithdrawalRootForProfile(request toybatch.CommandRequest) (string, error) {
	if profileUsesExperimentalSingleEntryWitnesses(request.ProfileName) {
		return computeExperimentalWithdrawalRootFromRequest(request)
	}
	return computeGenericWithdrawalRootFromRequest(request)
}

func computeExperimentalWithdrawalRootFromRequest(request toybatch.CommandRequest) (string, error) {
	if len(request.WithdrawalLeaves) == 0 {
		return hashPayloadDisplayHex(buildWithdrawalRootPayload(0, make([]byte, 32))), nil
	}
	if len(request.WithdrawalLeaves) > 1 {
		return "", fmt.Errorf("experimental real profile supports at most one withdrawal leaf")
	}

	leaf := request.WithdrawalLeaves[0]
	amount, err := parseAmountSatsField(leaf.Amount, "withdrawal_leaves[0].amount")
	if err != nil {
		return "", err
	}
	leafPayload := make([]byte, 0, len(withdrawalLeafMagic)+32+8+32)
	leafPayload = append(leafPayload, withdrawalLeafMagic...)
	leafPayload = append(leafPayload, uint256HexToLEBytes(leaf.WithdrawalID)...)
	var amountBytes [8]byte
	binary.LittleEndian.PutUint64(amountBytes[:], amount.Uint64())
	leafPayload = append(leafPayload, amountBytes[:]...)
	leafPayload = append(leafPayload, uint256HexToLEBytes(leaf.DestinationCommitment)...)
	leafHash := hashPayloadBytes(leafPayload)
	return hashPayloadDisplayHex(buildWithdrawalRootPayload(1, leafHash)), nil
}

func computeGenericWithdrawalRootFromRequest(request toybatch.CommandRequest) (string, error) {
	if len(request.WithdrawalLeaves) == 0 {
		if !request.WithdrawalLeavesSupplied &&
			request.RequireWithdrawalWitnessOnRootChange &&
			request.CurrentWithdrawalRoot != "" {
			return normalizeHex(request.CurrentWithdrawalRoot), nil
		}
		return hashPayloadDisplayHex(buildWithdrawalRootPayload(0, make([]byte, 32))), nil
	}

	levelHashes := make([][]byte, 0, len(request.WithdrawalLeaves))
	for index, leaf := range request.WithdrawalLeaves {
		amount, err := parseAmountSatsField(leaf.Amount, fmt.Sprintf("withdrawal_leaves[%d].amount", index))
		if err != nil {
			return "", err
		}
		leafPayload := make([]byte, 0, len(withdrawalLeafMagic)+32+8+32)
		leafPayload = append(leafPayload, withdrawalLeafMagic...)
		leafPayload = append(leafPayload, uint256HexToLEBytes(leaf.WithdrawalID)...)
		var amountBytes [8]byte
		binary.LittleEndian.PutUint64(amountBytes[:], amount.Uint64())
		leafPayload = append(leafPayload, amountBytes[:]...)
		leafPayload = append(leafPayload, uint256HexToLEBytes(leaf.DestinationCommitment)...)
		levelHashes = append(levelHashes, hashPayloadBytes(leafPayload))
	}

	for len(levelHashes) > 1 {
		nextLevel := make([][]byte, 0, (len(levelHashes)+1)/2)
		for i := 0; i < len(levelHashes); i += 2 {
			left := levelHashes[i]
			right := left
			if i+1 < len(levelHashes) {
				right = levelHashes[i+1]
			}
			parentPayload := make([]byte, 0, len(withdrawalNodeMagic)+len(left)+len(right))
			parentPayload = append(parentPayload, withdrawalNodeMagic...)
			parentPayload = append(parentPayload, left...)
			parentPayload = append(parentPayload, right...)
			nextLevel = append(nextLevel, hashPayloadBytes(parentPayload))
		}
		levelHashes = nextLevel
	}

	return hashPayloadDisplayHex(buildWithdrawalRootPayload(uint32(len(request.WithdrawalLeaves)), levelHashes[0])), nil
}

func buildWithdrawalRootPayload(leafCount uint32, merkleRoot []byte) []byte {
	payload := make([]byte, 0, len(withdrawalRootMagic)+4+32)
	payload = append(payload, withdrawalRootMagic...)
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], leafCount)
	payload = append(payload, count[:]...)
	payload = append(payload, merkleRoot...)
	return payload
}

func computeQueueStepDisplayHex(
	magic []uint8,
	sidechainID uint8,
	priorRoot string,
	entry toybatch.ConsumedQueueEntry,
) string {
	payload := make([]byte, 0, len(magic)+1+32+8+1+32+32)
	payload = append(payload, magic...)
	payload = append(payload, sidechainID)
	payload = append(payload, uint256HexToLEBytes(priorRoot)...)
	var queueIndex [8]byte
	binary.LittleEndian.PutUint64(queueIndex[:], entry.QueueIndex)
	payload = append(payload, queueIndex[:]...)
	payload = append(payload, entry.MessageKind)
	payload = append(payload, uint256HexToLEBytes(entry.MessageID)...)
	payload = append(payload, uint256HexToLEBytes(entry.MessageHash)...)
	return hashPayloadDisplayHex(payload)
}

func uint256HexToLEBytes(raw string) []byte {
	normalized := raw
	if normalized == "" {
		normalized = "0"
	}
	for len(normalized) < 64 {
		normalized = "0" + normalized
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		panic(err)
	}
	reversed := make([]byte, len(decoded))
	for i := range decoded {
		reversed[i] = decoded[len(decoded)-1-i]
	}
	return reversed
}

func hashPayloadBytes(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return append([]byte{}, second[:]...)
}

func hashPayloadDisplayHex(payload []byte) string {
	raw := hashPayloadBytes(payload)
	reversed := make([]byte, len(raw))
	for i := range raw {
		reversed[i] = raw[len(raw)-1-i]
	}
	return hex.EncodeToString(reversed)
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

func parseAmountSatsField(raw string, fieldName string) (*big.Int, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is required", fieldName)
	}
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) > 2 {
		return nil, fmt.Errorf("%s is not a valid amount", fieldName)
	}
	wholePart := parts[0]
	if wholePart == "" {
		wholePart = "0"
	}
	whole, ok := new(big.Int).SetString(wholePart, 10)
	if !ok || whole.Sign() < 0 {
		return nil, fmt.Errorf("%s is not a valid amount", fieldName)
	}
	fractional := "0"
	if len(parts) == 2 {
		fractional = parts[1]
		if len(fractional) > 8 {
			return nil, fmt.Errorf("%s has more than 8 decimal places", fieldName)
		}
		for len(fractional) < 8 {
			fractional += "0"
		}
	} else {
		fractional = "00000000"
	}
	fractionalValue, ok := new(big.Int).SetString(fractional, 10)
	if !ok {
		return nil, fmt.Errorf("%s is not a valid amount", fieldName)
	}
	sats := new(big.Int).Mul(whole, big.NewInt(100000000))
	sats.Add(sats, fractionalValue)
	if sats.Sign() <= 0 || sats.BitLen() > 63 {
		return nil, fmt.Errorf("%s is out of range", fieldName)
	}
	if sats.Cmp(bls12381fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("%s does not fit BLS12-381 scalar field", fieldName)
	}
	return sats, nil
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
