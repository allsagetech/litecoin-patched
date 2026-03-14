package toybatch

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const ProfileName = "gnark_groth16_toy_batch_transition_v1"
const NativeProfileName = "native_blst_groth16_toy_batch_transition_v1"

type BatchPublicInputs struct {
	BatchNumber           uint32 `json:"batch_number"`
	PriorStateRoot        string `json:"prior_state_root"`
	NewStateRoot          string `json:"new_state_root"`
	L1MessageRootBefore   string `json:"l1_message_root_before"`
	L1MessageRootAfter    string `json:"l1_message_root_after"`
	ConsumedQueueMessages uint32 `json:"consumed_queue_messages"`
	WithdrawalRoot        string `json:"withdrawal_root"`
	DataRoot              string `json:"data_root"`
	DataSize              uint32 `json:"data_size"`
}

type CommandRequest struct {
	ProfileName  string            `json:"profile_name"`
	ArtifactDir  string            `json:"artifact_dir"`
	SidechainID  uint64            `json:"sidechain_id"`
	PublicInputs BatchPublicInputs `json:"public_inputs"`
	ProofBytesHex string           `json:"proof_bytes_hex,omitempty"`
}

type CommandResult struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	ProofBytesHex string `json:"proof_bytes_hex,omitempty"`
}

type ProfileManifest struct {
	Name             string   `json:"name"`
	Curve            string   `json:"curve"`
	Backend          string   `json:"backend"`
	ConsensusSafe    bool     `json:"consensus_safe"`
	PublicInputs     []string `json:"public_inputs"`
	ProvingKeyFile   string   `json:"proving_key_file"`
	VerifyingKeyFile string   `json:"verifying_key_file"`
}

type ToyBatchTransitionCircuit struct {
	SidechainID           frontend.Variable `gnark:",public"`
	BatchNumber           frontend.Variable `gnark:",public"`
	PriorStateRoot        frontend.Variable `gnark:",public"`
	NewStateRoot          frontend.Variable `gnark:",public"`
	ConsumedQueueMessages frontend.Variable `gnark:",public"`
	WithdrawalRoot        frontend.Variable `gnark:",public"`
	DataRoot              frontend.Variable `gnark:",public"`
	StateDelta            frontend.Variable
	WithdrawalDelta       frontend.Variable
	DataDelta             frontend.Variable
}

func (c *ToyBatchTransitionCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.BatchNumber, api.Add(c.SidechainID, 1))
	api.AssertIsEqual(c.StateDelta, c.ConsumedQueueMessages)
	api.AssertIsEqual(c.NewStateRoot, api.Add(c.PriorStateRoot, c.StateDelta))
	api.AssertIsEqual(c.WithdrawalRoot, api.Add(c.NewStateRoot, c.WithdrawalDelta))
	api.AssertIsEqual(c.DataRoot, api.Add(c.WithdrawalRoot, c.DataDelta))
	return nil
}

func ReadProfileManifest(artifactDir string) (ProfileManifest, error) {
	var manifest ProfileManifest

	contents, err := os.ReadFile(filepath.Join(artifactDir, "profile.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Name != ProfileName {
		return manifest, fmt.Errorf("unexpected profile name %q", manifest.Name)
	}
	if manifest.VerifyingKeyFile == "" {
		return manifest, fmt.Errorf("profile missing verifying key file")
	}
	return manifest, nil
}

func DecodeProofHex(proofHex string) ([]byte, error) {
	if proofHex == "" {
		return nil, fmt.Errorf("proof_bytes_hex is required")
	}
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, err
	}
	if len(proofBytes) == 0 {
		return nil, fmt.Errorf("proof_bytes_hex decoded to empty proof")
	}
	return proofBytes, nil
}

func BuildPublicAssignment(request CommandRequest) (ToyBatchTransitionCircuit, error) {
	priorStateRoot, err := parseFieldHex(request.PublicInputs.PriorStateRoot, "prior_state_root")
	if err != nil {
		return ToyBatchTransitionCircuit{}, err
	}
	newStateRoot, err := parseFieldHex(request.PublicInputs.NewStateRoot, "new_state_root")
	if err != nil {
		return ToyBatchTransitionCircuit{}, err
	}
	withdrawalRoot, err := parseFieldHex(request.PublicInputs.WithdrawalRoot, "withdrawal_root")
	if err != nil {
		return ToyBatchTransitionCircuit{}, err
	}
	dataRoot, err := parseFieldHex(request.PublicInputs.DataRoot, "data_root")
	if err != nil {
		return ToyBatchTransitionCircuit{}, err
	}

	return ToyBatchTransitionCircuit{
		SidechainID:           new(big.Int).SetUint64(request.SidechainID),
		BatchNumber:           new(big.Int).SetUint64(uint64(request.PublicInputs.BatchNumber)),
		PriorStateRoot:        priorStateRoot,
		NewStateRoot:          newStateRoot,
		ConsumedQueueMessages: new(big.Int).SetUint64(uint64(request.PublicInputs.ConsumedQueueMessages)),
		WithdrawalRoot:        withdrawalRoot,
		DataRoot:              dataRoot,
	}, nil
}

func BuildFullAssignment(request CommandRequest) (ToyBatchTransitionCircuit, error) {
	assignment, err := BuildPublicAssignment(request)
	if err != nil {
		return ToyBatchTransitionCircuit{}, err
	}

	priorStateRoot := assignment.PriorStateRoot.(*big.Int)
	newStateRoot := assignment.NewStateRoot.(*big.Int)
	withdrawalRoot := assignment.WithdrawalRoot.(*big.Int)
	dataRoot := assignment.DataRoot.(*big.Int)
	consumedQueueMessages := assignment.ConsumedQueueMessages.(*big.Int)

	if newStateRoot.Cmp(priorStateRoot) < 0 {
		return ToyBatchTransitionCircuit{}, fmt.Errorf("new_state_root must be >= prior_state_root for toy circuit")
	}
	if withdrawalRoot.Cmp(newStateRoot) < 0 {
		return ToyBatchTransitionCircuit{}, fmt.Errorf("withdrawal_root must be >= new_state_root for toy circuit")
	}
	if dataRoot.Cmp(withdrawalRoot) < 0 {
		return ToyBatchTransitionCircuit{}, fmt.Errorf("data_root must be >= withdrawal_root for toy circuit")
	}

	stateDelta := new(big.Int).Sub(newStateRoot, priorStateRoot)
	if stateDelta.Cmp(consumedQueueMessages) != 0 {
		return ToyBatchTransitionCircuit{}, fmt.Errorf("new_state_root - prior_state_root must equal consumed_queue_messages")
	}

	assignment.StateDelta = stateDelta
	assignment.WithdrawalDelta = new(big.Int).Sub(withdrawalRoot, newStateRoot)
	assignment.DataDelta = new(big.Int).Sub(dataRoot, withdrawalRoot)
	return assignment, nil
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
