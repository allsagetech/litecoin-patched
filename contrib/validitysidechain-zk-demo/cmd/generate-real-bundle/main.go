package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/nativegroth16"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/realbatch"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/rs/zerolog"
)

const outputArtifactDir = "..\\..\\artifacts\\validitysidechain\\groth16_bls12_381_poseidon_v1"

type outputFile struct {
	Path     string `json:"path"`
	Encoding string `json:"encoding"`
	Contents string `json:"contents"`
}

type bundle struct {
	OutputRoot string       `json:"output_root"`
	Files      []outputFile `json:"files"`
}

type consensusTuple struct {
	Version              uint8 `json:"version"`
	ProofSystemID        uint8 `json:"proof_system_id"`
	CircuitFamilyID      uint8 `json:"circuit_family_id"`
	VerifierID           uint8 `json:"verifier_id"`
	PublicInputVersion   uint8 `json:"public_input_version"`
	StateRootFormat      uint8 `json:"state_root_format"`
	DepositMessageFormat uint8 `json:"deposit_message_format"`
	WithdrawalLeafFormat uint8 `json:"withdrawal_leaf_format"`
	BalanceLeafFormat    uint8 `json:"balance_leaf_format"`
	DataAvailabilityMode uint8 `json:"data_availability_mode"`
}

type proofVectors struct {
	Valid   []string `json:"valid"`
	Invalid []string `json:"invalid"`
}

type profileManifest struct {
	Name             string         `json:"name"`
	Curve            string         `json:"curve"`
	Backend          string         `json:"backend"`
	ConsensusSafe    bool           `json:"consensus_safe"`
	Status           string         `json:"status"`
	ConsensusTuple   consensusTuple `json:"consensus_tuple"`
	PublicInputs     []string       `json:"public_inputs"`
	VerifyingKeyFile string         `json:"verifying_key_file"`
	ProvingKeyFile   string         `json:"proving_key_file"`
	ProofVectors     proofVectors   `json:"proof_vectors"`
}

type vectorFile struct {
	Name                string                     `json:"name"`
	Circuit             string                     `json:"circuit"`
	Curve               string                     `json:"curve"`
	ExpectedResult      string                     `json:"expected_result"`
	PublicInputs        map[string]string          `json:"public_inputs"`
	SetupDeposits       []depositSetup             `json:"setup_deposits,omitempty"`
	ConsumedQueueEntries []toybatch.ConsumedQueueEntry `json:"consumed_queue_entries,omitempty"`
	DataChunksHex       []string                   `json:"data_chunks_hex,omitempty"`
	ProofBytesHex       string                     `json:"proof_bytes_hex"`
	Notes               []string                   `json:"notes,omitempty"`
}

type depositSetup struct {
	DestinationCommitment string `json:"destination_commitment"`
	RefundScript          string `json:"refund_script"`
	Amount                string `json:"amount"`
	Nonce                 uint64 `json:"nonce"`
	DepositID             string `json:"deposit_id"`
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	outputRoot, err := filepath.Abs(outputArtifactDir)
	if err != nil {
		panic(err)
	}

	deposit, queueRootBefore, queueRootAfter, queuePrefixCommitment := findFieldSizedDepositSetup(9)
	depositMessageHash := computeDepositMessageHash(9, deposit)
	if depositMessageHash == "" {
		panic("deposit message hash unexpectedly empty")
	}

	request := toybatch.CommandRequest{
		ProfileName: realbatch.ProfileName,
		SidechainID: 9,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           1,
			PriorStateRoot:        "1",
			NewStateRoot:          "0",
			L1MessageRootBefore:   queueRootBefore,
			L1MessageRootAfter:    queueRootAfter,
			ConsumedQueueMessages: 1,
			QueuePrefixCommitment: queuePrefixCommitment,
			WithdrawalRoot:        "0",
			DataRoot:              "0",
			DataSize:              0,
		},
		DataChunksHex: []string{
			hex.EncodeToString([]byte("real-batch")),
			hex.EncodeToString([]byte("-da")),
		},
		ConsumedQueueEntries: []toybatch.ConsumedQueueEntry{{
			QueueIndex:  0,
			MessageKind: 1,
			MessageID:   deposit.DepositID,
			MessageHash: depositMessageHash,
		}},
	}
	derivedRequest, err := realbatch.DeriveRequest(request)
	if err != nil {
		panic(err)
	}
	assignment, err := realbatch.BuildAssignment(derivedRequest)
	if err != nil {
		panic(err)
	}

	var circuit realbatch.PoseidonBatchTransitionCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	var rawProof bytes.Buffer
	if _, err := proof.WriteTo(&rawProof); err != nil {
		panic(err)
	}
	var rawVK bytes.Buffer
	if _, err := vk.WriteTo(&rawVK); err != nil {
		panic(err)
	}
	var rawPK bytes.Buffer
	if _, err := pk.WriteTo(&rawPK); err != nil {
		panic(err)
	}

	var nativeProof groth16bls12381.Proof
	if _, err := nativeProof.ReadFrom(bytes.NewReader(rawProof.Bytes())); err != nil {
		panic(err)
	}
	var nativeVK groth16bls12381.VerifyingKey
	if _, err := nativeVK.ReadFrom(bytes.NewReader(rawVK.Bytes())); err != nil {
		panic(err)
	}

	validProofBytes := nativegroth16.EncodeProof(&nativeProof)
	corruptProofBytes := append([]byte{}, validProofBytes...)
	corruptProofBytes[len(corruptProofBytes)-1] ^= 0x01

	validVector := vectorFile{
		Name:           "valid_proof",
		Circuit:        "poseidon_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "accept_in_native_verifier",
		PublicInputs:   publicInputsMap(derivedRequest),
		SetupDeposits:  []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		DataChunksHex:  append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:  hex.EncodeToString(validProofBytes),
		Notes: []string{
			"real Groth16 proof for the experimental poseidon batch transition circuit",
			"consumes one deterministic deposit queue entry and binds its queue prefix commitment",
			"the queued roots and commitment were chosen to fit the BLS12-381 scalar field",
			"binds a non-empty published DA payload through data_root and data_size",
			"verified in-process by the node native blst Groth16 path",
		},
	}
	mismatchRequest := derivedRequest
	mismatchRequest.PublicInputs.NewStateRoot = "2"
	mismatchVector := vectorFile{
		Name:           "public_input_mismatch",
		Circuit:        "poseidon_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   publicInputsMap(mismatchRequest),
		SetupDeposits:  []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		DataChunksHex:  append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:  hex.EncodeToString(validProofBytes),
		Notes: []string{
			"reuses the valid proof against mismatched public inputs",
		},
	}
	corruptVector := vectorFile{
		Name:           "corrupt_proof",
		Circuit:        "poseidon_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   publicInputsMap(derivedRequest),
		SetupDeposits:  []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		DataChunksHex:  append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:  hex.EncodeToString(corruptProofBytes),
		Notes: []string{
			"derived from the valid native proof by flipping one byte",
		},
	}

	manifest := profileManifest{
		Name:          realbatch.ProfileName,
		Curve:         "bls12_381",
		Backend:       "native_blst_groth16",
		ConsensusSafe: false,
		Status:        "experimental real Groth16 profile with deterministic Poseidon2 transition semantics and non-empty queue/DA test vectors",
		ConsensusTuple: consensusTuple{
			Version:              1,
			ProofSystemID:        2,
			CircuitFamilyID:      1,
			VerifierID:           1,
			PublicInputVersion:   2,
			StateRootFormat:      2,
			DepositMessageFormat: 1,
			WithdrawalLeafFormat: 2,
			BalanceLeafFormat:    2,
			DataAvailabilityMode: 1,
		},
		PublicInputs: []string{
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
		},
		VerifyingKeyFile: "batch_vk.bin",
		ProvingKeyFile:   "batch_pk.bin",
		ProofVectors: proofVectors{
			Valid:   []string{"valid/valid_proof.json"},
			Invalid: []string{"invalid/corrupt_proof.json", "invalid/public_input_mismatch.json"},
		},
	}

	out := bundle{
		OutputRoot: outputRoot,
		Files: []outputFile{
			utf8File("profile.json", mustJSON(manifest)),
			base64File("batch_vk.bin", nativegroth16.EncodeVerificationKey(&nativeVK)),
			base64File("batch_pk.bin", rawPK.Bytes()),
			utf8File("valid/valid_proof.json", mustJSON(validVector)),
			utf8File("invalid/corrupt_proof.json", mustJSON(corruptVector)),
			utf8File("invalid/public_input_mismatch.json", mustJSON(mismatchVector)),
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}

func findFieldSizedDepositSetup(sidechainID uint8) (depositSetup, string, string, string) {
	base := depositSetup{
		DestinationCommitment: "3333333333333333333333333333333333333333333333333333333333333333",
		RefundScript:          "00141111111111111111111111111111111111111111",
		Amount:                "1.0",
		DepositID:             "4444444444444444444444444444444444444444444444444444444444444444",
	}
	for nonce := uint64(1); nonce < 100000; nonce++ {
		candidate := base
		candidate.Nonce = nonce
		depositMessageHash := computeDepositMessageHash(sidechainID, candidate)
		queueRootBefore := computeQueueTransitionRoot(
			[]byte{'V', 'S', 'C', 'Q', 'A', 0x01},
			sidechainID,
			"0",
			0,
			1,
			candidate.DepositID,
			depositMessageHash,
		)
		queueRootAfter := computeQueueTransitionRoot(
			[]byte{'V', 'S', 'C', 'Q', 'C', 0x01},
			sidechainID,
			queueRootBefore,
			0,
			1,
			candidate.DepositID,
			depositMessageHash,
		)
		queuePrefixCommitment := computeQueueTransitionRoot(
			[]byte{'V', 'S', 'C', 'Q', 'P', 0x01},
			sidechainID,
			"0",
			0,
			1,
			candidate.DepositID,
			depositMessageHash,
		)
		if fitsField(queueRootBefore) && fitsField(queueRootAfter) && fitsField(queuePrefixCommitment) {
			return candidate, queueRootBefore, queueRootAfter, queuePrefixCommitment
		}
	}
	panic("failed to find field-sized queue roots for experimental real profile")
}

func publicInputsMap(request toybatch.CommandRequest) map[string]string {
	return map[string]string{
		"sidechain_id":            itoa(uint64(request.SidechainID)),
		"batch_number":            itoa(uint64(request.PublicInputs.BatchNumber)),
		"prior_state_root":        request.PublicInputs.PriorStateRoot,
		"new_state_root":          request.PublicInputs.NewStateRoot,
		"l1_message_root_before":  request.PublicInputs.L1MessageRootBefore,
		"l1_message_root_after":   request.PublicInputs.L1MessageRootAfter,
		"consumed_queue_messages": itoa(uint64(request.PublicInputs.ConsumedQueueMessages)),
		"queue_prefix_commitment": request.PublicInputs.QueuePrefixCommitment,
		"withdrawal_root":         request.PublicInputs.WithdrawalRoot,
		"data_root":               request.PublicInputs.DataRoot,
		"data_size":               itoa(uint64(request.PublicInputs.DataSize)),
	}
}

func itoa(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func computeDepositMessageHash(sidechainID uint8, deposit depositSetup) string {
	refundCommitment := hashPayloadDisplayHex(mustHex(deposit.RefundScript))
	payload := make([]byte, 0, 1+112)
	payload = append(payload, sidechainID)
	payload = append(payload, uint256HexToLEBytes(deposit.DepositID)...)
	var amount [8]byte
	binary.LittleEndian.PutUint64(amount[:], 100_000_000)
	payload = append(payload, amount[:]...)
	payload = append(payload, uint256HexToLEBytes(deposit.DestinationCommitment)...)
	payload = append(payload, uint256HexToLEBytes(refundCommitment)...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], deposit.Nonce)
	payload = append(payload, nonce[:]...)
	return hashPayloadDisplayHex(append([]byte{'V', 'S', 'C', 'D', 0x01}, payload...))
}

func computeQueueTransitionRoot(
	magic []byte,
	sidechainID uint8,
	priorRoot string,
	queueIndex uint64,
	messageKind uint8,
	messageID string,
	messageHash string,
) string {
	payload := make([]byte, 0, len(magic)+1+32+8+1+32+32)
	payload = append(payload, magic...)
	payload = append(payload, sidechainID)
	payload = append(payload, uint256HexToLEBytes(priorRoot)...)
	var index [8]byte
	binary.LittleEndian.PutUint64(index[:], queueIndex)
	payload = append(payload, index[:]...)
	payload = append(payload, messageKind)
	payload = append(payload, uint256HexToLEBytes(messageID)...)
	payload = append(payload, uint256HexToLEBytes(messageHash)...)
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
	decoded := mustHex(normalized)
	reversed := make([]byte, len(decoded))
	for i := range decoded {
		reversed[i] = decoded[len(decoded)-1-i]
	}
	return reversed
}

func hashPayloadDisplayHex(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	reversed := make([]byte, len(second))
	for i := range second {
		reversed[i] = second[len(second)-1-i]
	}
	return hex.EncodeToString(reversed)
}

func mustHex(raw string) []byte {
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return decoded
}

func fitsField(raw string) bool {
	value, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		panic(fmt.Sprintf("invalid field hex %q", raw))
	}
	return value.Cmp(bls12381fr.Modulus()) < 0
}

func mustJSON(value any) string {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func utf8File(path string, contents string) outputFile {
	return outputFile{Path: filepath.ToSlash(path), Encoding: "utf8", Contents: contents}
}

func base64File(path string, contents []byte) outputFile {
	return outputFile{Path: filepath.ToSlash(path), Encoding: "base64", Contents: base64.StdEncoding.EncodeToString(contents)}
}
