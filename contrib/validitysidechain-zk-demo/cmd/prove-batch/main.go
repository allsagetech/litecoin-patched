package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/nativegroth16"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/realbatch"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
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

	switch request.ProfileName {
	case toybatch.ProfileName:
		proveToyProfile(request)
	default:
		if realbatch.IsSupportedProfileName(request.ProfileName) {
			proveRealProfile(request)
			return
		}
		emit(toybatch.CommandResult{Error: "unexpected profile name"})
	}
}

func proveToyProfile(request toybatch.CommandRequest) {
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

func proveRealProfile(request toybatch.CommandRequest) {
	derivedRequest, err := realbatch.DeriveRequest(request)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}
	if err := realbatch.ValidateDerivedRequest(request); err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	manifest, err := readRealProfileManifest(request.ArtifactDir, request.ProfileName)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	assignment, err := realbatch.BuildAssignment(derivedRequest)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	circuit, err := realbatch.NewCircuit(request.ProfileName)
	if err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
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

	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
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

	var nativeProof groth16bls12381.Proof
	if _, err := nativeProof.ReadFrom(bytes.NewReader(proofBytes.Bytes())); err != nil {
		emit(toybatch.CommandResult{Error: err.Error()})
		return
	}

	emit(toybatch.CommandResult{
		OK:            true,
		ProofBytesHex: hex.EncodeToString(nativegroth16.EncodeProof(&nativeProof)),
	})
}

func readRealProfileManifest(artifactDir string, expectedProfileName string) (toybatch.ProfileManifest, error) {
	var manifest toybatch.ProfileManifest
	contents, err := os.ReadFile(filepath.Join(artifactDir, "profile.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Name != expectedProfileName {
		return manifest, os.ErrInvalid
	}
	if manifest.ProvingKeyFile == "" {
		return manifest, os.ErrInvalid
	}
	return manifest, nil
}

func emit(result toybatch.CommandResult) {
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(result); err != nil {
		panic(err)
	}
}
