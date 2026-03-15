package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/nativegroth16"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/realbatch"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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
		verifyToyProfile(request)
	case realbatch.ProfileName:
		verifyRealProfile(request)
	default:
		emit(toybatch.CommandResult{OK: false, Error: "unexpected profile name"})
	}
}

func verifyToyProfile(request toybatch.CommandRequest) {
	manifest, err := toybatch.ReadProfileManifest(request.ArtifactDir)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	publicAssignment, err := toybatch.BuildPublicAssignment(request)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}
	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	proofBytes, err := toybatch.DecodeProofHex(request.ProofBytesHex)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	vkFile, err := os.Open(filepath.Join(request.ArtifactDir, manifest.VerifyingKeyFile))
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	emit(toybatch.CommandResult{OK: true})
}

func verifyRealProfile(request toybatch.CommandRequest) {
	manifest, err := readRealProfileManifest(request.ArtifactDir)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	publicAssignment, err := realbatch.BuildPublicAssignment(request)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}
	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	proofBytes, err := toybatch.DecodeProofHex(request.ProofBytesHex)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}
	proof, err := nativegroth16.DecodeProof(proofBytes)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	vkBytes, err := os.ReadFile(filepath.Join(request.ArtifactDir, manifest.VerifyingKeyFile))
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}
	vk, err := nativegroth16.DecodeVerificationKey(vkBytes)
	if err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		emit(toybatch.CommandResult{OK: false, Error: err.Error()})
		return
	}

	emit(toybatch.CommandResult{OK: true})
}

func readRealProfileManifest(artifactDir string) (toybatch.ProfileManifest, error) {
	var manifest toybatch.ProfileManifest
	contents, err := os.ReadFile(filepath.Join(artifactDir, "profile.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Name != realbatch.ProfileName {
		return manifest, os.ErrInvalid
	}
	if manifest.VerifyingKeyFile == "" {
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
