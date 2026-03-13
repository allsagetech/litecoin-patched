package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/rs/zerolog"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	var request toybatch.CommandRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}
	if request.ProfileName != toybatch.ProfileName {
		emit(toybatch.CommandResult{Error: "unexpected profile name"})
		return
	}

	manifest, err := toybatch.ReadProfileManifest(request.ArtifactDir)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}
	if manifest.ProvingKeyFile == "" {
		emit(toybatch.CommandResult{Error: "profile missing proving key file"})
		return
	}

	fullAssignment, err := toybatch.BuildFullAssignment(request)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	var circuit toybatch.ToyBatchTransitionCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	pkFile, err := os.Open(filepath.Join(request.ArtifactDir, manifest.ProvingKeyFile))
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BLS12_381)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	witness, err := frontend.NewWitness(&fullAssignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	var proofBytes bytes.Buffer
	if _, err := proof.WriteTo(&proofBytes); err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	emit(toybatch.CommandResult{
		OK:            true,
		ProofBytesHex: hex.EncodeToString(proofBytes.Bytes()),
	})
}

func emit(result toybatch.CommandResult) {
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(result); err != nil {
		panic(err)
	}
}
