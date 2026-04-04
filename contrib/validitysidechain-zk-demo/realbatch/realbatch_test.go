package realbatch

import (
	"strings"
	"testing"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
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

func TestValidateDerivedRequestV2RejectsQueueWitnessOverLimit(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.PublicInputs.ConsumedQueueMessages = FinalProfileMaxConsumedQueueEntries + 1
	request.ConsumedQueueEntries = append(request.ConsumedQueueEntries,
		toybatch.ConsumedQueueEntry{
			QueueIndex:  2,
			MessageKind: 1,
			MessageID:   strings.Repeat("aa", 32),
			MessageHash: strings.Repeat("bb", 32),
		},
	)
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

	err = ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized consumed_queue_entries")
	}
	if err.Error() != "consumed_queue_entries length exceeds v2 circuit witness limit of 2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDerivedRequestV2RejectsWithdrawalWitnessOverLimit(t *testing.T) {
	request := buildV2RequestForTest(t)
	request.WithdrawalLeaves = append(request.WithdrawalLeaves,
		toybatch.WithdrawalLeaf{
			WithdrawalID:          strings.Repeat("10", 32),
			Amount:                "0.25",
			DestinationCommitment: strings.Repeat("20", 32),
		},
	)
	derived, err := DeriveRequest(request)
	if err != nil {
		t.Fatalf("DeriveRequest returned unexpected error: %v", err)
	}
	request.PublicInputs.NewStateRoot = derived.PublicInputs.NewStateRoot
	request.PublicInputs.WithdrawalRoot = derived.PublicInputs.WithdrawalRoot

	err = ValidateDerivedRequest(request)
	if err == nil {
		t.Fatal("ValidateDerivedRequest succeeded for oversized withdrawal_leaves")
	}
	if err.Error() != "withdrawal_leaves length exceeds v2 circuit witness limit of 2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCircuitPublicInputCountsMatchManifest(t *testing.T) {
	testCases := []struct {
		name               string
		profileName        string
		publicInputVersion uint8
	}{
		{
			name:               "poseidon_v1",
			profileName:        ProfileName,
			publicInputVersion: ExperimentalPublicInputVersion,
		},
		{
			name:               "poseidon_v2",
			profileName:        FinalProfileName,
			publicInputVersion: FinalPublicInputVersion,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			circuit, err := NewCircuit(tc.profileName)
			if err != nil {
				t.Fatalf("NewCircuit returned unexpected error: %v", err)
			}

			ccs, err := CompileCircuit(tc.profileName, circuit)
			if err != nil {
				t.Fatalf("CompileCircuit returned unexpected error: %v", err)
			}

			manifestInputs, err := ManifestPublicInputs(tc.publicInputVersion)
			if err != nil {
				t.Fatalf("ManifestPublicInputs returned unexpected error: %v", err)
			}

			// Gnark counts the implicit ONE wire as a public variable, while the
			// manifest and native verifier asset layout enumerate only explicit
			// batch public inputs.
			gotExplicitPublic := ccs.GetNbPublicVariables() - 1
			if gotExplicitPublic != len(manifestInputs) {
				t.Fatalf("compiled circuit exposes %d explicit public variables, want %d", gotExplicitPublic, len(manifestInputs))
			}
		})
	}
}

func buildV2RequestForTest(t *testing.T) toybatch.CommandRequest {
	t.Helper()

	request := toybatch.CommandRequest{
		ProfileName: FinalProfileName,
		SidechainID: 57,
		PublicInputs: toybatch.BatchPublicInputs{
			BatchNumber:           1,
			PriorStateRoot:        "1",
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
