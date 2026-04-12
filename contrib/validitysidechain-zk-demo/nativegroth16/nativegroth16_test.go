package nativegroth16

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type noCommitmentCircuit struct {
	One frontend.Variable
}

func (c *noCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	return nil
}

type commitmentCircuit struct {
	One frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	committer, ok := api.Compiler().(frontend.Committer)
	if !ok {
		return nil
	}
	commitment, err := committer.Commit(c.One)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

func setupProofAndVK(
	t *testing.T,
	circuit frontend.Circuit,
	assignment frontend.Circuit,
) (*groth16bls12381.Proof, *groth16bls12381.VerifyingKey, witness.Witness) {
	t.Helper()

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("frontend.Compile returned unexpected error: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16.Setup returned unexpected error: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("frontend.NewWitness returned unexpected error: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("witness.Public returned unexpected error: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("groth16.Prove returned unexpected error: %v", err)
	}

	nativeProof, ok := proof.(*groth16bls12381.Proof)
	if !ok {
		t.Fatal("proof did not use the expected BLS12-381 backend type")
	}
	nativeVK, ok := vk.(*groth16bls12381.VerifyingKey)
	if !ok {
		t.Fatal("verifying key did not use the expected BLS12-381 backend type")
	}
	return nativeProof, nativeVK, publicWitness
}

func TestEncodeProofAndVerificationKeyRoundTripNativeNoCommitmentCircuit(t *testing.T) {
	proof, vk, publicWitness := setupProofAndVK(
		t,
		&noCommitmentCircuit{},
		&noCommitmentCircuit{One: 1},
	)

	encodedProof, err := EncodeProof(proof)
	if err != nil {
		t.Fatalf("EncodeProof returned unexpected error: %v", err)
	}
	encodedVK, err := EncodeVerificationKey(vk)
	if err != nil {
		t.Fatalf("EncodeVerificationKey returned unexpected error: %v", err)
	}

	decodedProof, err := DecodeProof(encodedProof)
	if err != nil {
		t.Fatalf("DecodeProof returned unexpected error: %v", err)
	}
	decodedVK, err := DecodeVerificationKey(encodedVK)
	if err != nil {
		t.Fatalf("DecodeVerificationKey returned unexpected error: %v", err)
	}
	if err := groth16.Verify(decodedProof, decodedVK, publicWitness); err != nil {
		t.Fatalf("groth16.Verify returned unexpected error: %v", err)
	}
}

func TestEncodeProofAndVerificationKeyRoundTripCommitmentAwareCircuit(t *testing.T) {
	proof, vk, publicWitness := setupProofAndVK(
		t,
		&commitmentCircuit{},
		&commitmentCircuit{One: 1},
	)

	encodedProof, err := EncodeProof(proof)
	if err != nil {
		t.Fatalf("EncodeProof returned unexpected error: %v", err)
	}
	encodedVK, err := EncodeVerificationKey(vk)
	if err != nil {
		t.Fatalf("EncodeVerificationKey returned unexpected error: %v", err)
	}

	decodedProof, err := DecodeProof(encodedProof)
	if err != nil {
		t.Fatalf("DecodeProof returned unexpected error: %v", err)
	}
	decodedVK, err := DecodeVerificationKey(encodedVK)
	if err != nil {
		t.Fatalf("DecodeVerificationKey returned unexpected error: %v", err)
	}

	if len(decodedProof.Commitments) != len(proof.Commitments) {
		t.Fatalf("decoded proof commitment count mismatch: got %d want %d", len(decodedProof.Commitments), len(proof.Commitments))
	}
	if len(decodedVK.CommitmentKeys) != len(vk.CommitmentKeys) {
		t.Fatalf("decoded verifying key commitment count mismatch: got %d want %d", len(decodedVK.CommitmentKeys), len(vk.CommitmentKeys))
	}
	if err := groth16.Verify(decodedProof, decodedVK, publicWitness); err != nil {
		t.Fatalf("groth16.Verify returned unexpected error: %v", err)
	}
}
