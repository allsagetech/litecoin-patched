package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/nativegroth16"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/realbatch"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog"
)

const outputArtifactDirV1 = "..\\..\\artifacts\\validitysidechain\\groth16_bls12_381_poseidon_v1"
const outputArtifactDirV2 = "..\\..\\artifacts\\validitysidechain\\groth16_bls12_381_poseidon_v2"

type bundleSpec struct {
	profileName                  string
	outputArtifactDir            string
	publicInputVersion           uint8
	circuitName                  string
	status                       string
	validNotes                   []string
	requireFieldSizedQueueRoots  bool
	requireFieldSizedWithdrawal  bool
}

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
	Name                 string                        `json:"name"`
	Circuit              string                        `json:"circuit"`
	Curve                string                        `json:"curve"`
	ExpectedResult       string                        `json:"expected_result"`
	PublicInputs         map[string]string             `json:"public_inputs"`
	SetupDeposits        []depositSetup                `json:"setup_deposits,omitempty"`
	ConsumedQueueEntries []toybatch.ConsumedQueueEntry `json:"consumed_queue_entries,omitempty"`
	WithdrawalLeaves     []toybatch.WithdrawalLeaf     `json:"withdrawal_leaves,omitempty"`
	DataChunksHex        []string                      `json:"data_chunks_hex,omitempty"`
	ProofBytesHex        string                        `json:"proof_bytes_hex"`
	Notes                []string                      `json:"notes,omitempty"`
}

type depositSetup struct {
	DestinationCommitment string `json:"destination_commitment"`
	RefundScript          string `json:"refund_script"`
	Amount                string `json:"amount"`
	Nonce                 uint64 `json:"nonce"`
	DepositID             string `json:"deposit_id"`
}

type withdrawalSetup struct {
	WithdrawalID          string `json:"withdrawal_id"`
	Amount                string `json:"amount"`
	Script                string `json:"script"`
	DestinationCommitment string `json:"destination_commitment"`
}

func resolveBundleSpec(profileName string) (bundleSpec, error) {
	switch profileName {
	case realbatch.ProfileName:
		return bundleSpec{
			profileName:                 realbatch.ProfileName,
			outputArtifactDir:           outputArtifactDirV1,
			publicInputVersion:          realbatch.ExperimentalPublicInputVersion,
			circuitName:                 "poseidon_batch_transition_v1",
			status:                      "experimental real Groth16 profile with deterministic Poseidon2 transition semantics, host-validated queue/withdrawal fixtures, and non-empty DA test vectors",
			requireFieldSizedQueueRoots: true,
			requireFieldSizedWithdrawal: true,
			validNotes: []string{
				"real Groth16 proof for the experimental poseidon batch transition circuit",
				"includes one deterministic deposit queue entry fixture validated host-side and reused by surrounding node-side queue checks",
				"includes one deterministic withdrawal leaf fixture validated host-side and reused by surrounding node-side withdrawal execution checks",
				"binds withdrawal_root directly into the Poseidon transition commitment",
				"the queued roots and commitment were chosen to fit the BLS12-381 scalar field",
				"binds a non-empty published DA payload through data_root and data_size",
				"verified in-process by the node native blst Groth16 path",
			},
		}, nil
	case realbatch.FinalProfileName:
		return bundleSpec{
			profileName:                 realbatch.FinalProfileName,
			outputArtifactDir:           outputArtifactDirV2,
			publicInputVersion:          realbatch.FinalPublicInputVersion,
			circuitName:                 "poseidon_batch_transition_v2",
			status:                      "experimental decomposed-input Poseidon Groth16 profile with full-width queue, withdrawal, and DA roots plus host-validated queue/withdrawal fixtures",
			requireFieldSizedQueueRoots: false,
			requireFieldSizedWithdrawal: false,
			validNotes: []string{
				"real Groth16 proof for the decomposed-input experimental poseidon batch transition circuit",
				"includes one deterministic deposit queue entry fixture validated host-side and reused by surrounding node-side queue checks",
				"includes one deterministic withdrawal leaf fixture validated host-side and reused by surrounding node-side withdrawal execution checks",
				"binds queue, withdrawal, and DA roots through 128-bit public-input limbs instead of single-field encodings",
				"the queued roots and/or withdrawal root intentionally exceed the BLS12-381 scalar field to exercise the decomposed public-input layout",
				"binds a non-empty published DA payload through data_root and data_size",
				"verified in-process by the node native blst Groth16 path",
			},
		}, nil
	default:
		return bundleSpec{}, fmt.Errorf("unsupported profile name %q", profileName)
	}
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	profileName := flag.String("profile", realbatch.ProfileName, "profile name to generate")
	flag.Parse()

	spec, err := resolveBundleSpec(*profileName)
	if err != nil {
		panic(err)
	}

	outputRoot, err := filepath.Abs(spec.outputArtifactDir)
	if err != nil {
		panic(err)
	}

	deposit, queueRootBefore, queueRootAfter, queuePrefixCommitment := findDepositSetup(9, spec.requireFieldSizedQueueRoots)
	depositMessageHash := computeDepositMessageHash(9, deposit)
	if depositMessageHash == "" {
		panic("deposit message hash unexpectedly empty")
	}
	withdrawal, withdrawalRoot := findWithdrawalSetup(spec.requireFieldSizedWithdrawal)

	request := toybatch.CommandRequest{
		ProfileName: spec.profileName,
		SidechainID: 9,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           1,
			PriorStateRoot:        "1",
			NewStateRoot:          "0",
			L1MessageRootBefore:   queueRootBefore,
			L1MessageRootAfter:    queueRootAfter,
			ConsumedQueueMessages: 1,
			QueuePrefixCommitment: queuePrefixCommitment,
			WithdrawalRoot:        withdrawalRoot,
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
		WithdrawalLeaves: []toybatch.WithdrawalLeaf{{
			WithdrawalID:          withdrawal.WithdrawalID,
			Amount:                withdrawal.Amount,
			DestinationCommitment: withdrawal.DestinationCommitment,
			Script:                withdrawal.Script,
		}},
	}
	derivedRequest, err := realbatch.DeriveRequest(request)
	if err != nil {
		panic(err)
	}
	manifestPublicInputs, err := realbatch.ManifestPublicInputs(spec.publicInputVersion)
	if err != nil {
		panic(err)
	}
	if err := realbatch.ValidateDerivedRequest(derivedRequest); err != nil {
		panic(err)
	}
	assignment, err := realbatch.BuildAssignment(derivedRequest)
	if err != nil {
		panic(err)
	}
	validPublicInputs, err := realbatch.PublicInputsMap(derivedRequest, spec.publicInputVersion)
	if err != nil {
		panic(err)
	}

	circuit, err := realbatch.NewCircuit(spec.profileName)
	if err != nil {
		panic(err)
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
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
		Name:                 "valid_proof",
		Circuit:              spec.circuitName,
		Curve:                "bls12_381",
		ExpectedResult:       "accept_in_native_verifier",
		PublicInputs:         validPublicInputs,
		SetupDeposits:        []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		WithdrawalLeaves:     append([]toybatch.WithdrawalLeaf{}, derivedRequest.WithdrawalLeaves...),
		DataChunksHex:        append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:        hex.EncodeToString(validProofBytes),
		Notes:                append([]string{}, spec.validNotes...),
	}
	mismatchRequest := derivedRequest
	mismatchRequest.PublicInputs.NewStateRoot = "2"
	mismatchVector := vectorFile{
		Name:                 "public_input_mismatch",
		Circuit:              spec.circuitName,
		Curve:                "bls12_381",
		ExpectedResult:       "reject",
		PublicInputs:         mustPublicInputsMap(mismatchRequest, spec.publicInputVersion),
		SetupDeposits:        []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		WithdrawalLeaves:     append([]toybatch.WithdrawalLeaf{}, derivedRequest.WithdrawalLeaves...),
		DataChunksHex:        append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:        hex.EncodeToString(validProofBytes),
		Notes: []string{
			"reuses the valid proof against mismatched public inputs",
		},
	}
	withdrawalRootMismatchRequest := derivedRequest
	withdrawalRootMismatchRequest.PublicInputs.WithdrawalRoot = "2"
	withdrawalRootMismatchVector := vectorFile{
		Name:                 "withdrawal_root_mismatch",
		Circuit:              spec.circuitName,
		Curve:                "bls12_381",
		ExpectedResult:       "reject",
		PublicInputs:         mustPublicInputsMap(withdrawalRootMismatchRequest, spec.publicInputVersion),
		SetupDeposits:        []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		WithdrawalLeaves:     append([]toybatch.WithdrawalLeaf{}, derivedRequest.WithdrawalLeaves...),
		DataChunksHex:        append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:        hex.EncodeToString(validProofBytes),
		Notes: []string{
			"reuses the valid proof against a mismatched withdrawal_root public input",
		},
	}
	queuePrefixMismatchRequest := derivedRequest
	queuePrefixMismatchRequest.PublicInputs.QueuePrefixCommitment = "2"
	queuePrefixMismatchVector := vectorFile{
		Name:                 "queue_prefix_commitment_mismatch",
		Circuit:              spec.circuitName,
		Curve:                "bls12_381",
		ExpectedResult:       "reject",
		PublicInputs:         mustPublicInputsMap(queuePrefixMismatchRequest, spec.publicInputVersion),
		SetupDeposits:        []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		WithdrawalLeaves:     append([]toybatch.WithdrawalLeaf{}, derivedRequest.WithdrawalLeaves...),
		DataChunksHex:        append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:        hex.EncodeToString(validProofBytes),
		Notes: []string{
			"reuses the valid proof against a mismatched queue_prefix_commitment public input",
		},
	}
	corruptVector := vectorFile{
		Name:                 "corrupt_proof",
		Circuit:              spec.circuitName,
		Curve:                "bls12_381",
		ExpectedResult:       "reject",
		PublicInputs:         validPublicInputs,
		SetupDeposits:        []depositSetup{deposit},
		ConsumedQueueEntries: append([]toybatch.ConsumedQueueEntry{}, derivedRequest.ConsumedQueueEntries...),
		WithdrawalLeaves:     append([]toybatch.WithdrawalLeaf{}, derivedRequest.WithdrawalLeaves...),
		DataChunksHex:        append([]string{}, derivedRequest.DataChunksHex...),
		ProofBytesHex:        hex.EncodeToString(corruptProofBytes),
		Notes: []string{
			"derived from the valid native proof by flipping one byte",
		},
	}

	manifest := profileManifest{
		Name:          spec.profileName,
		Curve:         "bls12_381",
		Backend:       "native_blst_groth16",
		ConsensusSafe: false,
		Status:        spec.status,
		ConsensusTuple: consensusTuple{
			Version:              1,
			ProofSystemID:        2,
			CircuitFamilyID:      1,
			VerifierID:           1,
			PublicInputVersion:   spec.publicInputVersion,
			StateRootFormat:      2,
			DepositMessageFormat: 1,
			WithdrawalLeafFormat: 2,
			BalanceLeafFormat:    2,
			DataAvailabilityMode: 1,
		},
		PublicInputs:     manifestPublicInputs,
		VerifyingKeyFile: "batch_vk.bin",
		ProvingKeyFile:   "batch_pk.bin",
		ProofVectors: proofVectors{
			Valid: []string{"valid/valid_proof.json"},
			Invalid: []string{
				"invalid/corrupt_proof.json",
				"invalid/public_input_mismatch.json",
				"invalid/queue_prefix_commitment_mismatch.json",
				"invalid/withdrawal_root_mismatch.json",
			},
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
			utf8File("invalid/queue_prefix_commitment_mismatch.json", mustJSON(queuePrefixMismatchVector)),
			utf8File("invalid/withdrawal_root_mismatch.json", mustJSON(withdrawalRootMismatchVector)),
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}

func findDepositSetup(sidechainID uint8, requireFieldSized bool) (depositSetup, string, string, string) {
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
		allRootsFitField := fitsField(queueRootBefore) && fitsField(queueRootAfter) && fitsField(queuePrefixCommitment)
		if (requireFieldSized && allRootsFitField) || (!requireFieldSized && !allRootsFitField) {
			return candidate, queueRootBefore, queueRootAfter, queuePrefixCommitment
		}
	}
	if requireFieldSized {
		panic("failed to find field-sized queue roots for experimental real profile")
	}
	panic("failed to find non-field-sized queue roots for decomposed real profile")
}

func findWithdrawalSetup(requireFieldSized bool) (withdrawalSetup, string) {
	base := withdrawalSetup{
		Amount: "0.25",
		Script: "00142222222222222222222222222222222222222222",
	}
	base.DestinationCommitment = hashPayloadDisplayHex(mustHex(base.Script))
	for suffix := uint64(1); suffix < 100000; suffix++ {
		candidate := base
		candidate.WithdrawalID = fmt.Sprintf("%064x", suffix)
		root := computeWithdrawalRoot([]withdrawalSetup{candidate})
		rootFitsField := fitsField(root)
		if (requireFieldSized && rootFitsField) || (!requireFieldSized && !rootFitsField) {
			return candidate, root
		}
	}
	if requireFieldSized {
		panic("failed to find field-sized withdrawal root for experimental real profile")
	}
	panic("failed to find non-field-sized withdrawal root for decomposed real profile")
}

func mustPublicInputsMap(request toybatch.CommandRequest, publicInputVersion uint8) map[string]string {
	values, err := realbatch.PublicInputsMap(request, publicInputVersion)
	if err != nil {
		panic(err)
	}
	return values
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

func computeWithdrawalRoot(withdrawals []withdrawalSetup) string {
	if len(withdrawals) == 0 {
		payload := make([]byte, 0, 5+4+32)
		payload = append(payload, []byte{'V', 'S', 'C', 'W', 0x01}...)
		payload = append(payload, 0, 0, 0, 0)
		payload = append(payload, make([]byte, 32)...)
		return hashPayloadDisplayHex(payload)
	}

	leafPayload := make([]byte, 0, 5+32+8+32)
	leafPayload = append(leafPayload, []byte{'V', 'S', 'C', 'W', 0x02}...)
	leafPayload = append(leafPayload, uint256HexToLEBytes(withdrawals[0].WithdrawalID)...)
	var amount [8]byte
	binary.LittleEndian.PutUint64(amount[:], 25_000_000)
	leafPayload = append(leafPayload, amount[:]...)
	leafPayload = append(leafPayload, uint256HexToLEBytes(withdrawals[0].DestinationCommitment)...)
	leafHash := hashPayloadBytes(leafPayload)

	rootPayload := make([]byte, 0, 5+4+32)
	rootPayload = append(rootPayload, []byte{'V', 'S', 'C', 'W', 0x01}...)
	rootPayload = append(rootPayload, 1, 0, 0, 0)
	rootPayload = append(rootPayload, leafHash...)
	return hashPayloadDisplayHex(rootPayload)
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
	raw := hashPayloadBytes(payload)
	reversed := make([]byte, len(raw))
	for i := range raw {
		reversed[i] = raw[len(raw)-1-i]
	}
	return hex.EncodeToString(reversed)
}

func hashPayloadBytes(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return append([]byte{}, second[:]...)
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
