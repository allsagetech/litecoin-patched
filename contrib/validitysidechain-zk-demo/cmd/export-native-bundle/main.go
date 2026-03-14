package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/rs/zerolog"
)

const (
	sourceArtifactDir = "..\\..\\artifacts\\validitysidechain\\gnark_groth16_toy_batch_transition_v1"
	outputArtifactDir = "..\\..\\artifacts\\validitysidechain\\native_blst_groth16_toy_batch_transition_v1"
)

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
	ProofVectors     proofVectors   `json:"proof_vectors"`
}

type vectorFile struct {
	Name           string            `json:"name"`
	Circuit        string            `json:"circuit"`
	Curve          string            `json:"curve"`
	ExpectedResult string            `json:"expected_result"`
	PublicInputs   map[string]string `json:"public_inputs"`
	ProofBytesHex  string            `json:"proof_bytes_hex"`
	Notes          []string          `json:"notes,omitempty"`
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	sourceRoot, err := filepath.Abs(sourceArtifactDir)
	if err != nil {
		panic(err)
	}
	outputRoot, err := filepath.Abs(outputArtifactDir)
	if err != nil {
		panic(err)
	}

	sourceManifest, err := toybatch.ReadProfileManifest(sourceRoot)
	if err != nil {
		panic(err)
	}
	vkBytes, err := os.ReadFile(filepath.Join(sourceRoot, sourceManifest.VerifyingKeyFile))
	if err != nil {
		panic(err)
	}
	pkFile, err := os.Open(filepath.Join(sourceRoot, sourceManifest.ProvingKeyFile))
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()

	var circuit toybatch.ToyBatchTransitionCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	nativeRequest := toybatch.CommandRequest{
		ProfileName: toybatch.ProfileName,
		ArtifactDir: sourceRoot,
		SidechainID: 8,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           9,
			PriorStateRoot:        "1000",
			NewStateRoot:          "1003",
			L1MessageRootBefore:   "0",
			L1MessageRootAfter:    "0",
			ConsumedQueueMessages: 3,
			WithdrawalRoot:        "100e",
			DataRoot:              "101f",
			DataSize:              0,
		},
	}
	fullAssignment, err := toybatch.BuildFullAssignment(nativeRequest)
	if err != nil {
		panic(err)
	}

	pk := groth16.NewProvingKey(ecc.BLS12_381)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&fullAssignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	generatedProof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	var generatedProofBytes bytes.Buffer
	if _, err := generatedProof.WriteTo(&generatedProofBytes); err != nil {
		panic(err)
	}

	var proofObject groth16bls12381.Proof
	if _, err := proofObject.ReadFrom(bytes.NewReader(generatedProofBytes.Bytes())); err != nil {
		panic(err)
	}
	var vkObject groth16bls12381.VerifyingKey
	if _, err := vkObject.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		panic(err)
	}

	nativeProofBytes := encodeNativeProof(&proofObject)
	corruptProofBytes := append([]byte{}, nativeProofBytes...)
	corruptProofBytes[len(corruptProofBytes)-1] ^= 0x01
	nativeVKBytes := encodeNativeVerificationKey(&vkObject)

	profile := profileManifest{
		Name:          toybatch.NativeProfileName,
		Curve:         "bls12_381",
		Backend:       "native_blst_groth16",
		ConsensusSafe: false,
		Status:        "real toy Groth16 profile for in-process native blst verification",
		ConsensusTuple: consensusTuple{
			Version:              1,
			ProofSystemID:        3,
			CircuitFamilyID:      2,
			VerifierID:           2,
			PublicInputVersion:   4,
			StateRootFormat:      1,
			DepositMessageFormat: 1,
			WithdrawalLeafFormat: 1,
			BalanceLeafFormat:    1,
			DataAvailabilityMode: 1,
		},
		PublicInputs: []string{
			"sidechain_id",
			"batch_number",
			"prior_state_root",
			"new_state_root",
			"consumed_queue_messages",
			"withdrawal_root",
			"data_root",
		},
		VerifyingKeyFile: "batch_vk.bin",
		ProofVectors: proofVectors{
			Valid:   []string{"valid/valid_proof.json"},
			Invalid: []string{"invalid/corrupt_proof.json", "invalid/public_input_mismatch.json"},
		},
	}

	validPublicInputs := publicInputsMap(nativeRequest)
	mismatchPublicInputs := publicInputsMap(nativeRequest)
	mismatchPublicInputs["new_state_root"] = "1004"

	validVector := vectorFile{
		Name:           "valid_proof",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "accept_in_native_verifier",
		PublicInputs:   validPublicInputs,
		ProofBytesHex:  hex.EncodeToString(nativeProofBytes),
		Notes: []string{
			"real Groth16 proof for the toy demo circuit",
			"converted into the node-native proof encoding for in-process blst verification",
		},
	}
	corruptVector := vectorFile{
		Name:           "corrupt_proof",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   validPublicInputs,
		ProofBytesHex:  hex.EncodeToString(corruptProofBytes),
		Notes: []string{
			"derived from the native valid proof by flipping one byte",
		},
	}
	mismatchVector := vectorFile{
		Name:           "public_input_mismatch",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   mismatchPublicInputs,
		ProofBytesHex:  hex.EncodeToString(nativeProofBytes),
		Notes: []string{
			"reuses the native valid proof against a different public input set",
		},
	}

	out := bundle{
		OutputRoot: outputRoot,
		Files: []outputFile{
			utf8File("profile.json", mustJSON(profile)),
			base64File("batch_vk.bin", nativeVKBytes),
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

func encodeNativeProof(proof *groth16bls12381.Proof) []byte {
	out := []byte{'V', 'S', 'G', 'P', 0x01}
	a := proof.Ar.Bytes()
	b := proof.Bs.Bytes()
	c := proof.Krs.Bytes()
	out = append(out, a[:]...)
	out = append(out, b[:]...)
	out = append(out, c[:]...)
	return out
}

func encodeNativeVerificationKey(vk *groth16bls12381.VerifyingKey) []byte {
	out := []byte{'V', 'S', 'G', 'V', 'K', 0x01}
	out = appendUint32LE(out, uint32(len(vk.G1.K)-1))
	alpha := vk.G1.Alpha.Bytes()
	beta := vk.G2.Beta.Bytes()
	gamma := vk.G2.Gamma.Bytes()
	delta := vk.G2.Delta.Bytes()
	out = append(out, alpha[:]...)
	out = append(out, beta[:]...)
	out = append(out, gamma[:]...)
	out = append(out, delta[:]...)
	out = appendUint32LE(out, uint32(len(vk.G1.K)))
	for i := range vk.G1.K {
		point := vk.G1.K[i].Bytes()
		out = append(out, point[:]...)
	}
	return out
}

func appendUint32LE(dst []byte, value uint32) []byte {
	return append(dst,
		byte(value&0xff),
		byte((value>>8)&0xff),
		byte((value>>16)&0xff),
		byte((value>>24)&0xff),
	)
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func publicInputsMap(request toybatch.CommandRequest) map[string]string {
	return map[string]string{
		"sidechain_id":            fmt.Sprintf("%d", request.SidechainID),
		"batch_number":            fmt.Sprintf("%d", request.PublicInputs.BatchNumber),
		"prior_state_root":        request.PublicInputs.PriorStateRoot,
		"new_state_root":          request.PublicInputs.NewStateRoot,
		"consumed_queue_messages": fmt.Sprintf("%d", request.PublicInputs.ConsumedQueueMessages),
		"withdrawal_root":         request.PublicInputs.WithdrawalRoot,
		"data_root":               request.PublicInputs.DataRoot,
	}
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
