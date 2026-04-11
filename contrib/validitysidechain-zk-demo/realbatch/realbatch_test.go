package realbatch

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/nativegroth16"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestValidateDerivedRequestV2AcceptsGenericQueueAndWithdrawalWitnesses(t *testing.T) {
	request := buildV2RequestForTest(t)

	if err := ValidateDerivedRequest(request); err != nil {
		t.Fatalf("ValidateDerivedRequest returned unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsMismatchedGenericQueueWitness(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.ConsumedQueueEntries[1].MessageHash = strings.Repeat("66", 32)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for mismatched queue witness")
	}
	if err.Error() != "l1_message_root_after does not match consumed_queue_entries witness" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsMismatchedGenericWithdrawalWitness(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves[1].Amount = "0.18"

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for mismatched withdrawal witness")
	}
	if err.Error() != "withdrawal_root does not match withdrawal_leaves witness" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsCurrentStateRootMismatch(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.CurrentStateRoot = strings.Repeat("fe", 32)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for mismatched current_state_root")
	}
	if err.Error() != "prior_state_root does not match current_state_root" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsCurrentQueueRootMismatch(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.CurrentL1MessageRoot = strings.Repeat("fd", 32)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for mismatched current_l1_message_root")
	}
	if err.Error() != "l1_message_root_before does not match current_l1_message_root" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsWithdrawalRootChangeWithoutWitnessUnderPolicy(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves = nil
	request.WithdrawalLeavesSupplied = false
	request.PublicInputs.WithdrawalRoot = strings.Repeat("cc", 32)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for missing withdrawal witness under policy")
	}
	if err.Error() != "withdrawal_root changes require withdrawal_leaves witness under current witness policy" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeriveRequestV2PreservesCurrentWithdrawalRootWhenWitnessOmitted(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves = nil
	request.WithdrawalLeavesSupplied = false
	request.PublicInputs.WithdrawalRoot = request.CurrentWithdrawalRoot

	derived, err := DeriveRequest(request)
	if err != nil {
		t.Fatalf("DeriveRequest returned unexpected error: %v", err)
	}
	request.PublicInputs.NewStateRoot = derived.PublicInputs.NewStateRoot
	if normalizeHex(derived.PublicInputs.WithdrawalRoot) != normalizeHex(request.CurrentWithdrawalRoot) {
		t.Fatalf("derived withdrawal root %q does not preserve current root %q", derived.PublicInputs.WithdrawalRoot, request.CurrentWithdrawalRoot)
	}
	if err := ValidateDerivedRequest(request); err != nil {
		t.Fatalf("ValidateDerivedRequest returned unexpected error: %v", err)
	}
}

func TestDeriveRequestV2AllowsExplicitEmptyWithdrawalWitness(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves = nil
	request.WithdrawalLeavesSupplied = true
	emptyRoot, err := computeGenericWithdrawalRootFromRequest(request)
	if err != nil {
		t.Fatalf("computeGenericWithdrawalRootFromRequest returned unexpected error: %v", err)
	}
	request.PublicInputs.WithdrawalRoot = emptyRoot

	derived, err := DeriveRequest(request)
	if err != nil {
		t.Fatalf("DeriveRequest returned unexpected error: %v", err)
	}
	request.PublicInputs.NewStateRoot = derived.PublicInputs.NewStateRoot
	if normalizeHex(derived.PublicInputs.WithdrawalRoot) != normalizeHex(emptyRoot) {
		t.Fatalf("derived withdrawal root %q does not match explicit empty root %q", derived.PublicInputs.WithdrawalRoot, emptyRoot)
	}
	if err := ValidateDerivedRequest(request); err != nil {
		t.Fatalf("ValidateDerivedRequest returned unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsNonZeroDataSizeWithoutChunks(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.PublicInputs.DataSize = 1

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for non-zero data_size without chunks")
	}
	if err.Error() != "data_size does not match provided data_chunks_hex" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsNonZeroDataRootWithoutChunks(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.PublicInputs.DataRoot = strings.Repeat("dd", 32)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for non-zero data_root without chunks")
	}
	if err.Error() != "data_root does not match provided data_chunks_hex" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPoseidonV2NativeArtifactsRemainVerifierCompatible(t *testing.T) {
	request := buildV2RequestForTest(t)

	circuit, err := NewCircuit(FinalProfileName)
	if err != nil {
		t.Fatalf("NewCircuit returned unexpected error: %v", err)
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("frontend.Compile returned unexpected error: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16.Setup returned unexpected error: %v", err)
	}

	assignment, err := BuildAssignment(request)
	if err != nil {
		t.Fatalf("BuildAssignment returned unexpected error: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("frontend.NewWitness returned unexpected error: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("groth16.Prove returned unexpected error: %v", err)
	}

	publicAssignment, err := BuildPublicAssignment(request)
	if err != nil {
		t.Fatalf("BuildPublicAssignment returned unexpected error: %v", err)
	}
	publicWitness, err := frontend.NewWitness(publicAssignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("frontend.NewWitness(public) returned unexpected error: %v", err)
	}

	var rawProof bytes.Buffer
	if _, err := proof.WriteTo(&rawProof); err != nil {
		t.Fatalf("proof.WriteTo returned unexpected error: %v", err)
	}
	var nativeProof groth16bls12381.Proof
	if _, err := nativeProof.ReadFrom(bytes.NewReader(rawProof.Bytes())); err != nil {
		t.Fatalf("native proof ReadFrom returned unexpected error: %v", err)
	}
	encodedProof := nativegroth16.EncodeProof(&nativeProof)
	decodedProof, err := nativegroth16.DecodeProof(encodedProof)
	if err != nil {
		t.Fatalf("DecodeProof returned unexpected error: %v", err)
	}

	var rawVK bytes.Buffer
	if _, err := vk.WriteTo(&rawVK); err != nil {
		t.Fatalf("vk.WriteTo returned unexpected error: %v", err)
	}
	var nativeVK groth16bls12381.VerifyingKey
	if _, err := nativeVK.ReadFrom(bytes.NewReader(rawVK.Bytes())); err != nil {
		t.Fatalf("native verifying key ReadFrom returned unexpected error: %v", err)
	}
	encodedVK := nativegroth16.EncodeVerificationKey(&nativeVK)

	expectedPublicInputs, err := ManifestPublicInputs(FinalPublicInputVersion)
	if err != nil {
		t.Fatalf("ManifestPublicInputs returned unexpected error: %v", err)
	}
	const verifyingKeyMagicLen = 6
	publicInputCount := binary.LittleEndian.Uint32(encodedVK[verifyingKeyMagicLen : verifyingKeyMagicLen+4])
	if publicInputCount != uint32(len(expectedPublicInputs)) {
		t.Fatalf("native verifying key exported %d public inputs, want %d", publicInputCount, len(expectedPublicInputs))
	}

	decodedVK, err := nativegroth16.DecodeVerificationKey(encodedVK)
	if err != nil {
		t.Fatalf("DecodeVerificationKey returned unexpected error: %v", err)
	}
	if err := groth16.Verify(decodedProof, decodedVK, publicWitness); err != nil {
		t.Fatalf("groth16.Verify returned unexpected error: %v", err)
	}
}

func buildV2RequestForTest(t *testing.T) toybatch.CommandRequest {
	t.Helper()

	emptyDataRoot := computePublishedDataRoot(nil)
	request := toybatch.CommandRequest{
		ProfileName: FinalProfileName,
		SidechainID: 57,
		CurrentStateRoot: strings.Repeat("01", 32),
		CurrentWithdrawalRoot: strings.Repeat("02", 32),
		CurrentDataRoot: emptyDataRoot,
		CurrentL1MessageRoot: strings.Repeat("ab", 32),
		RequireWithdrawalWitnessOnRootChange: true,
		WithdrawalLeavesSupplied: true,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           1,
			PriorStateRoot:        strings.Repeat("01", 32),
			NewStateRoot:          "0",
			L1MessageRootBefore:   strings.Repeat("ab", 32),
			L1MessageRootAfter:    "0",
			ConsumedQueueMessages: 2,
			QueuePrefixCommitment: "0",
			WithdrawalRoot:        "0",
			DataRoot:              emptyDataRoot,
			DataSize:              0,
		},
		ConsumedQueueEntries: []toybatch.ConsumedQueueEntry{
			{
				QueueIndex:  0,
				MessageKind: 1,
				MessageID:   strings.Repeat("11", 32),
				MessageHash: strings.Repeat("22", 32),
			},
			{
				QueueIndex:  1,
				MessageKind: 2,
				MessageID:   strings.Repeat("33", 32),
				MessageHash: strings.Repeat("44", 32),
			},
		},
		WithdrawalLeaves: []toybatch.WithdrawalLeaf{
			{
				WithdrawalID:          strings.Repeat("55", 32),
				Amount:                "0.15",
				DestinationCommitment: strings.Repeat("77", 32),
			},
			{
				WithdrawalID:          strings.Repeat("88", 32),
				Amount:                "0.20",
				DestinationCommitment: strings.Repeat("99", 32),
			},
		},
	}

	request.PublicInputs.L1MessageRootAfter = computeConsumedQueueRootForTest(
		uint8(request.SidechainID),
		request.PublicInputs.L1MessageRootBefore,
		request.ConsumedQueueEntries,
	)
	request.PublicInputs.QueuePrefixCommitment = computeQueuePrefixCommitmentForTest(
		uint8(request.SidechainID),
		request.ConsumedQueueEntries,
	)

	derived, err := DeriveRequest(request)
	if err != nil {
		t.Fatalf("DeriveRequest returned unexpected error: %v", err)
	}
	request.PublicInputs.NewStateRoot = derived.PublicInputs.NewStateRoot
	request.PublicInputs.WithdrawalRoot = derived.PublicInputs.WithdrawalRoot
	return request
}

func computeConsumedQueueRootForTest(
	sidechainID uint8,
	priorRoot string,
	entries []toybatch.ConsumedQueueEntry,
) string {
	root := priorRoot
	for _, entry := range entries {
		root = computeQueueStepDisplayHex(queueConsumeMagic, sidechainID, root, entry)
	}
	return root
}

func computeQueuePrefixCommitmentForTest(
	sidechainID uint8,
	entries []toybatch.ConsumedQueueEntry,
) string {
	commitment := "0"
	for _, entry := range entries {
		commitment = computeQueueStepDisplayHex(queuePrefixCommitmentMagic, sidechainID, commitment, entry)
	}
	return commitment
}
