package main

import (
	"encoding/json"
	"os"

	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/realbatch"
	"github.com/allsagetech/litecoin-patched/contrib/validitysidechain-zk-demo/toybatch"
	"github.com/rs/zerolog"
)

type deriveResult struct {
	OK           bool                       `json:"ok"`
	Error        string                     `json:"error,omitempty"`
	PublicInputs *toybatch.BatchPublicInputs `json:"public_inputs,omitempty"`
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	var request toybatch.CommandRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		emit(deriveResult{Error: err.Error()})
		return
	}

	if !realbatch.IsSupportedProfileName(request.ProfileName) {
		emit(deriveResult{Error: "unexpected profile name"})
		return
	}

	derived, err := realbatch.DeriveRequest(request)
	if err != nil {
		emit(deriveResult{Error: err.Error()})
		return
	}

	emit(deriveResult{
		OK:           true,
		PublicInputs: &derived.PublicInputs,
	})
}

func emit(result deriveResult) {
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(result); err != nil {
		panic(err)
	}
}
