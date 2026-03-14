package realbatch

import (
	"fmt"
	"math/big"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidon2native "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	gnarkhash "github.com/consensys/gnark/std/hash"
	poseidon2circuit "github.com/consensys/gnark/std/permutation/poseidon2"
)

const ProfileName = "groth16_bls12_381_poseidon_v1"

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
}

func (c *PoseidonBatchTransitionCircuit) Define(api frontend.API) error {
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

func DeriveRequest(request toybatch.CommandRequest) (toybatch.CommandRequest, error) {
	assignment, err := BuildAssignment(ensureDerivedTargetsCleared(request))
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
	derived.PublicInputs.NewStateRoot = formatFieldHex(newStateRoot)
	derived.PublicInputs.WithdrawalRoot = formatFieldHex(withdrawalRoot)
	return derived, nil
}

func ValidateDerivedRequest(request toybatch.CommandRequest) error {
	derived, err := DeriveRequest(request)
	if err != nil {
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
