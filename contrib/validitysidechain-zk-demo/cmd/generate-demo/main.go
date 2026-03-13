package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/rs/zerolog"
)

const outputDirName = "generated/toy_batch_transition_bls12_381_v1"

type ToyBatchTransitionCircuit struct {
	SidechainID            frontend.Variable `gnark:",public"`
	BatchNumber            frontend.Variable `gnark:",public"`
	PriorStateRoot         frontend.Variable `gnark:",public"`
	NewStateRoot           frontend.Variable `gnark:",public"`
	ConsumedQueueMessages  frontend.Variable `gnark:",public"`
	WithdrawalRoot         frontend.Variable `gnark:",public"`
	DataRoot               frontend.Variable `gnark:",public"`
	StateDelta             frontend.Variable
	WithdrawalDelta        frontend.Variable
	DataDelta              frontend.Variable
}

func (c *ToyBatchTransitionCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.BatchNumber, api.Add(c.SidechainID, 1))
	api.AssertIsEqual(c.StateDelta, c.ConsumedQueueMessages)
	api.AssertIsEqual(c.NewStateRoot, api.Add(c.PriorStateRoot, c.StateDelta))
	api.AssertIsEqual(c.WithdrawalRoot, api.Add(c.NewStateRoot, c.WithdrawalDelta))
	api.AssertIsEqual(c.DataRoot, api.Add(c.WithdrawalRoot, c.DataDelta))
	return nil
}

type DemoPublicInputs struct {
	SidechainID           string `json:"sidechain_id"`
	BatchNumber           string `json:"batch_number"`
	PriorStateRoot        string `json:"prior_state_root"`
	NewStateRoot          string `json:"new_state_root"`
	ConsumedQueueMessages string `json:"consumed_queue_messages"`
	WithdrawalRoot        string `json:"withdrawal_root"`
	DataRoot              string `json:"data_root"`
}

type DemoVector struct {
	Name           string           `json:"name"`
	Circuit        string           `json:"circuit"`
	Curve          string           `json:"curve"`
	ExpectedResult string           `json:"expected_result"`
	PublicInputs   DemoPublicInputs `json:"public_inputs"`
	ProofBytesHex  string           `json:"proof_bytes_hex"`
	Notes          []string         `json:"notes"`
}

type DemoProfile struct {
	Name                 string   `json:"name"`
	Curve                string   `json:"curve"`
	Backend              string   `json:"backend"`
	ConsensusSafe        bool     `json:"consensus_safe"`
	Generator            string   `json:"generator"`
	PublicInputs         []string `json:"public_inputs"`
	VerifyingKeyFile     string   `json:"verifying_key_file"`
	ValidVectorFile      string   `json:"valid_vector_file"`
	InvalidVectorFiles   []string `json:"invalid_vector_files"`
}

type OutputFile struct {
	Path     string `json:"path"`
	Encoding string `json:"encoding"`
	Contents string `json:"contents"`
}

type DemoBundle struct {
	OutputRoot string       `json:"output_root"`
	Files      []OutputFile `json:"files"`
}

func mustJSON(value any) []byte {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}

func serializeWriterTo(writer interface{ WriteTo(io.Writer) (int64, error) }) []byte {
	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func publicInputsFromAssignment(assignment ToyBatchTransitionCircuit) DemoPublicInputs {
	return DemoPublicInputs{
		SidechainID:           fmt.Sprint(assignment.SidechainID),
		BatchNumber:           fmt.Sprint(assignment.BatchNumber),
		PriorStateRoot:        fmt.Sprint(assignment.PriorStateRoot),
		NewStateRoot:          fmt.Sprint(assignment.NewStateRoot),
		ConsumedQueueMessages: fmt.Sprint(assignment.ConsumedQueueMessages),
		WithdrawalRoot:        fmt.Sprint(assignment.WithdrawalRoot),
		DataRoot:              fmt.Sprint(assignment.DataRoot),
	}
}

func outputFile(path, encoding string, contents []byte) OutputFile {
	encodedContents := string(contents)
	if encoding == "base64" {
		encodedContents = base64.StdEncoding.EncodeToString(contents)
	}
	return OutputFile{
		Path:     path,
		Encoding: encoding,
		Contents: encodedContents,
	}
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	var circuit ToyBatchTransitionCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	validAssignment := ToyBatchTransitionCircuit{
		SidechainID:           7,
		BatchNumber:           8,
		PriorStateRoot:        1000,
		NewStateRoot:          1003,
		ConsumedQueueMessages: 3,
		WithdrawalRoot:        1014,
		DataRoot:              1031,
		StateDelta:            3,
		WithdrawalDelta:       11,
		DataDelta:             17,
	}

	witness, err := frontend.NewWitness(&validAssignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}

	vkBytes := serializeWriterTo(vk)
	proofBytes := serializeWriterTo(proof)

	corruptProofBytes := append([]byte{}, proofBytes...)
	if len(corruptProofBytes) > 0 {
		corruptProofBytes[len(corruptProofBytes)-1] ^= 0x01
	}

	validVector := DemoVector{
		Name:           "valid_proof",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "accept_in_demo_verifier",
		PublicInputs:   publicInputsFromAssignment(validAssignment),
		ProofBytesHex:  hex.EncodeToString(proofBytes),
		Notes: []string{
			"real Groth16 proof for the toy demo circuit",
			"not the real Litecoin validity-sidechain circuit",
		},
	}

	invalidCorruptVector := DemoVector{
		Name:           "corrupt_proof",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   publicInputsFromAssignment(validAssignment),
		ProofBytesHex:  hex.EncodeToString(corruptProofBytes),
		Notes: []string{
			"derived from the valid proof by flipping one byte",
		},
	}

	mismatchedAssignment := validAssignment
	mismatchedAssignment.NewStateRoot = 1004
	invalidMismatchVector := DemoVector{
		Name:           "public_input_mismatch",
		Circuit:        "toy_batch_transition_v1",
		Curve:          "bls12_381",
		ExpectedResult: "reject",
		PublicInputs:   publicInputsFromAssignment(mismatchedAssignment),
		ProofBytesHex:  hex.EncodeToString(proofBytes),
		Notes: []string{
			"reuses the valid proof against a different public input set",
		},
	}

	profile := DemoProfile{
		Name:          "toy_batch_transition_bls12_381_v1",
		Curve:         "bls12_381",
		Backend:       "gnark_groth16",
		ConsensusSafe: false,
		Generator:     "contrib/validitysidechain-zk-demo/cmd/generate-demo",
		PublicInputs: []string{
			"sidechain_id",
			"batch_number",
			"prior_state_root",
			"new_state_root",
			"consumed_queue_messages",
			"withdrawal_root",
			"data_root",
		},
		VerifyingKeyFile:   "verifying_key.bin",
		ValidVectorFile:    "valid/valid_proof.json",
		InvalidVectorFiles: []string{"invalid/corrupt_proof.json", "invalid/public_input_mismatch.json"},
	}

	bundle := DemoBundle{
		OutputRoot: outputDirName,
		Files: []OutputFile{
			outputFile("profile.json", "utf8", mustJSON(profile)),
			outputFile("verifying_key.bin", "base64", vkBytes),
			outputFile("valid/valid_proof.bin", "base64", proofBytes),
			outputFile("valid/valid_proof.json", "utf8", mustJSON(validVector)),
			outputFile("invalid/corrupt_proof.bin", "base64", corruptProofBytes),
			outputFile("invalid/corrupt_proof.json", "utf8", mustJSON(invalidCorruptVector)),
			outputFile("invalid/public_input_mismatch.json", "utf8", mustJSON(invalidMismatchVector)),
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bundle); err != nil {
		panic(err)
	}
}
