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

func TestValidateProofRequestContractV2RejectsMissingCurrentStateRoot(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.CurrentStateRoot = ""

	err := ValidateProofRequestContract(request)
	if err == nil {
		t.Fatal("ValidateProofRequestContract succeeded without current_state_root")
	}
	if err.Error() != "current_state_root is required for legacy v2 proof requests" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProofRequestContractV2RejectsImplicitDataChunksVector(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.DataChunksHex = nil

	err := ValidateProofRequestContract(request)
	if err == nil {
		t.Fatal("ValidateProofRequestContract succeeded without explicit data_chunks_hex")
	}
	if err.Error() != "data_chunks_hex must be provided explicitly for legacy v2 proof requests" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsWithdrawalRootChangeWithoutWitnessUnderPolicy(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves = []toybatch.WithdrawalLeaf{}
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
	request.WithdrawalLeaves = []toybatch.WithdrawalLeaf{}
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
	request.WithdrawalLeaves = []toybatch.WithdrawalLeaf{}
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

func TestDeriveRequestV2DerivesQueueBindingsAndPublishedDataWitness(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.PublicInputs.L1MessageRootAfter = "0"
	request.PublicInputs.QueuePrefixCommitment = "0"
	request.PublicInputs.DataRoot = "0"
	request.PublicInputs.DataSize = 0
	request.DataChunksHex = []string{"aa", "bbbb"}

	derived, err := DeriveRequest(request)
	if err != nil {
		t.Fatalf("DeriveRequest returned unexpected error: %v", err)
	}

	expectedQueueRoot := computeConsumedQueueRootForTest(
		uint8(request.SidechainID),
		request.PublicInputs.L1MessageRootBefore,
		request.ConsumedQueueEntries,
	)
	expectedQueuePrefix := computeQueuePrefixCommitmentForTest(
		uint8(request.SidechainID),
		request.ConsumedQueueEntries,
	)
	expectedDataRoot := computePublishedDataRoot([][]byte{{0xaa}, {0xbb, 0xbb}})

	if normalizeHex(derived.PublicInputs.L1MessageRootAfter) != normalizeHex(expectedQueueRoot) {
		t.Fatalf("derived l1_message_root_after %q does not match expected %q", derived.PublicInputs.L1MessageRootAfter, expectedQueueRoot)
	}
	if normalizeHex(derived.PublicInputs.QueuePrefixCommitment) != normalizeHex(expectedQueuePrefix) {
		t.Fatalf("derived queue_prefix_commitment %q does not match expected %q", derived.PublicInputs.QueuePrefixCommitment, expectedQueuePrefix)
	}
	if normalizeHex(derived.PublicInputs.DataRoot) != normalizeHex(expectedDataRoot) {
		t.Fatalf("derived data_root %q does not match expected %q", derived.PublicInputs.DataRoot, expectedDataRoot)
	}
	if derived.PublicInputs.DataSize != 3 {
		t.Fatalf("derived data_size %d does not match expected 3", derived.PublicInputs.DataSize)
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
	encodedProof, err := nativegroth16.EncodeProof(&nativeProof)
	if err != nil {
		t.Fatalf("EncodeProof returned unexpected error: %v", err)
	}
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
	encodedVK, err := nativegroth16.EncodeVerificationKey(&nativeVK)
	if err != nil {
		t.Fatalf("EncodeVerificationKey returned unexpected error: %v", err)
	}

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

func TestPoseidonV3NativeArtifactsExportCommitmentMetadata(t *testing.T) {
	request := buildV3RequestForTest(t)

	circuit, err := NewCircuit(CommitmentProfileName)
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
	if len(nativeProof.Commitments) == 0 {
		t.Fatal("native proof omitted commitment metadata for v3 circuit")
	}
	encodedProof, err := nativegroth16.EncodeProof(&nativeProof)
	if err != nil {
		t.Fatalf("EncodeProof returned unexpected error: %v", err)
	}
	decodedProof, err := nativegroth16.DecodeProof(encodedProof)
	if err != nil {
		t.Fatalf("DecodeProof returned unexpected error: %v", err)
	}
	if len(decodedProof.Commitments) == 0 {
		t.Fatal("decoded native proof omitted commitment metadata for v3 circuit")
	}

	var rawVK bytes.Buffer
	if _, err := vk.WriteTo(&rawVK); err != nil {
		t.Fatalf("vk.WriteTo returned unexpected error: %v", err)
	}
	var nativeVK groth16bls12381.VerifyingKey
	if _, err := nativeVK.ReadFrom(bytes.NewReader(rawVK.Bytes())); err != nil {
		t.Fatalf("native verifying key ReadFrom returned unexpected error: %v", err)
	}
	if len(nativeVK.CommitmentKeys) == 0 || len(nativeVK.PublicAndCommitmentCommitted) == 0 {
		t.Fatal("native verifying key omitted commitment metadata for v3 circuit")
	}
	encodedVK, err := nativegroth16.EncodeVerificationKey(&nativeVK)
	if err != nil {
		t.Fatalf("EncodeVerificationKey returned unexpected error: %v", err)
	}

	expectedPublicInputs, err := ManifestPublicInputs(CommitmentPublicInputVersion)
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
	if len(decodedVK.CommitmentKeys) == 0 || len(decodedVK.PublicAndCommitmentCommitted) == 0 {
		t.Fatal("decoded native verifying key omitted commitment metadata for v3 circuit")
	}
	if err := groth16.Verify(decodedProof, decodedVK, publicWitness); err != nil {
		t.Fatalf("groth16.Verify returned unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV3RejectsMultipleDataChunkWitnesses(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.DataChunksHex = []string{"aa", "bb", "cc"}

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized data chunk witnesses")
	}
	if err.Error() != "canonical v3 profile supports at most 2 data chunk witnesses" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProofRequestContractV3RejectsMissingCurrentStateRoot(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.CurrentStateRoot = ""

	err := ValidateProofRequestContract(request)
	if err == nil {
		t.Fatal("ValidateProofRequestContract succeeded without current_state_root")
	}
	if err.Error() != "current_state_root is required for canonical v3 proof requests" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeriveRequestV3PreservesCurrentWithdrawalRootWhenWitnessOmitted(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.WithdrawalLeaves = []toybatch.WithdrawalLeaf{}
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

func TestValidateDerivedRequestV3RejectsMoreThanTwoQueueWitnessEntries(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.PublicInputs.ConsumedQueueMessages = 3
	request.ConsumedQueueEntries = append(
		append([]toybatch.ConsumedQueueEntry{}, request.ConsumedQueueEntries...),
		toybatch.ConsumedQueueEntry{
			QueueIndex:  2,
			MessageKind: 1,
			MessageID:   strings.Repeat("33", 32),
			MessageHash: strings.Repeat("44", 32),
		},
	)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized queue witness")
	}
	if err.Error() != "canonical v3 profile supports at most 2 consumed queue entries" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV3RejectsMoreThanTwoWithdrawalLeafWitnesses(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.WithdrawalLeaves = append(
		append([]toybatch.WithdrawalLeaf{}, request.WithdrawalLeaves...),
		toybatch.WithdrawalLeaf{
			WithdrawalID:          strings.Repeat("aa", 32),
			Amount:                "0.05",
			DestinationCommitment: strings.Repeat("bb", 32),
		},
	)

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized withdrawal witness")
	}
	if err.Error() != "canonical v3 profile supports at most 2 withdrawal leaf witnesses" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV3RejectsOversizedDataChunkWitness(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.DataChunksHex = []string{strings.Repeat("aa", commitmentDataWitnessMaxChunkBytes+1)}

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized data chunk witness")
	}
	expected := "data_chunks_hex[0] exceeds the canonical v3 witness limit of 64 bytes"
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV3RejectsNonFinalChunkShorterThanWitnessWidth(t *testing.T) {
	request := buildV3RequestForTest(t)
	request.DataChunksHex = []string{"aa", "bb"}

	err := ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for a short non-final data chunk witness")
	}
	expected := "data_chunks_hex[0] must be exactly 64 bytes when followed by another chunk in the canonical v3 profile"
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func buildV2RequestForTest(t *testing.T) toybatch.CommandRequest {
	t.Helper()

	emptyDataRoot := computePublishedDataRoot(nil)
	request := toybatch.CommandRequest{
		ProfileName:                          FinalProfileName,
		SidechainID:                          57,
		CurrentStateRoot:                     strings.Repeat("01", 32),
		CurrentWithdrawalRoot:                strings.Repeat("02", 32),
		CurrentDataRoot:                      emptyDataRoot,
		CurrentL1MessageRoot:                 strings.Repeat("ab", 32),
		RequireWithdrawalWitnessOnRootChange: true,
		WithdrawalLeavesSupplied:             true,
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
		DataChunksHex: []string{},
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

func buildV3RequestForTest(t *testing.T) toybatch.CommandRequest {
	t.Helper()

	emptyDataRoot := computePublishedDataRoot(nil)
	request := toybatch.CommandRequest{
		ProfileName:                          CommitmentProfileName,
		SidechainID:                          57,
		CurrentStateRoot:                     strings.Repeat("01", 32),
		CurrentWithdrawalRoot:                strings.Repeat("02", 32),
		CurrentDataRoot:                      emptyDataRoot,
		CurrentL1MessageRoot:                 strings.Repeat("ab", 32),
		RequireWithdrawalWitnessOnRootChange: true,
		WithdrawalLeavesSupplied:             true,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           1,
			PriorStateRoot:        strings.Repeat("01", 32),
			NewStateRoot:          "0",
			L1MessageRootBefore:   strings.Repeat("ab", 32),
			L1MessageRootAfter:    "0",
			ConsumedQueueMessages: 2,
			QueuePrefixCommitment: "0",
			WithdrawalRoot:        "0",
			DataRoot:              "0",
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
		DataChunksHex: []string{strings.Repeat("61", commitmentDataWitnessMaxChunkBytes), "2d6461"},
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
	request.PublicInputs.DataRoot = derived.PublicInputs.DataRoot
	request.PublicInputs.DataSize = derived.PublicInputs.DataSize
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
