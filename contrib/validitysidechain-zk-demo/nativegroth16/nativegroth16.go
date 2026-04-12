package nativegroth16

import (
	"encoding/binary"
	"fmt"
	"math"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

var proofMagic = []byte{'V', 'S', 'G', 'P', 0x01}
var verifyingKeyMagic = []byte{'V', 'S', 'G', 'V', 'K', 0x01}

func EncodeProof(proof *groth16bls12381.Proof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("native Groth16 proof is required")
	}
	out := append([]byte{}, proofMagic...)
	a := proof.Ar.Bytes()
	b := proof.Bs.Bytes()
	c := proof.Krs.Bytes()
	out = append(out, a[:]...)
	out = append(out, b[:]...)
	out = append(out, c[:]...)
	if len(proof.Commitments) != 0 {
		out = appendUint32LE(out, uint32(len(proof.Commitments)))
		for i := range proof.Commitments {
			point := proof.Commitments[i].Bytes()
			out = append(out, point[:]...)
		}
		pok := proof.CommitmentPok.Bytes()
		out = append(out, pok[:]...)
	}
	return out, nil
}

func EncodeVerificationKey(vk *groth16bls12381.VerifyingKey) ([]byte, error) {
	if vk == nil {
		return nil, fmt.Errorf("native Groth16 verifying key is required")
	}
	if len(vk.CommitmentKeys) != len(vk.PublicAndCommitmentCommitted) {
		return nil, fmt.Errorf("native Groth16 verifying key commitment metadata is inconsistent")
	}
	if len(vk.G1.K) < 1+len(vk.CommitmentKeys) {
		return nil, fmt.Errorf("native Groth16 verifying key gamma_abc layout is inconsistent")
	}
	out := append([]byte{}, verifyingKeyMagic...)
	out = appendUint32LE(out, uint32(len(vk.G1.K)-1-len(vk.CommitmentKeys)))
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
	if len(vk.CommitmentKeys) != 0 {
		out = appendUint32LE(out, uint32(len(vk.CommitmentKeys)))
		for i := range vk.CommitmentKeys {
			out = appendUint32LE(out, uint32(len(vk.PublicAndCommitmentCommitted[i])))
			for _, wireIndex := range vk.PublicAndCommitmentCommitted[i] {
				if wireIndex < 0 || wireIndex > math.MaxUint32 {
					return nil, fmt.Errorf("native Groth16 verifying key witness index is out of range")
				}
				out = appendUint32LE(out, uint32(wireIndex))
			}
			g := vk.CommitmentKeys[i].G.Bytes()
			gSigmaNeg := vk.CommitmentKeys[i].GSigmaNeg.Bytes()
			out = append(out, g[:]...)
			out = append(out, gSigmaNeg[:]...)
		}
	}
	return out, nil
}

func DecodeProof(encoded []byte) (*groth16bls12381.Proof, error) {
	const baseLen = 5 + 48 + 96 + 48
	if len(encoded) < baseLen {
		return nil, fmt.Errorf("native Groth16 proof bytes have unexpected length")
	}
	if string(encoded[:len(proofMagic)]) != string(proofMagic) {
		return nil, fmt.Errorf("native Groth16 proof bytes have invalid magic")
	}

	proof := new(groth16bls12381.Proof)
	offset := len(proofMagic)
	if _, err := proof.Ar.SetBytes(encoded[offset : offset+48]); err != nil {
		return nil, err
	}
	offset += 48
	if _, err := proof.Bs.SetBytes(encoded[offset : offset+96]); err != nil {
		return nil, err
	}
	offset += 96
	if _, err := proof.Krs.SetBytes(encoded[offset : offset+48]); err != nil {
		return nil, err
	}
	offset += 48
	if offset == len(encoded) {
		return proof, nil
	}

	if len(encoded)-offset < 4 {
		return nil, fmt.Errorf("native Groth16 proof bytes have unexpected length")
	}
	commitmentCount := binary.LittleEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	if commitmentCount == 0 {
		return nil, fmt.Errorf("native Groth16 proof commitment extension is malformed")
	}
	expectedLen := baseLen + 4 + int(commitmentCount)*48 + 48
	if len(encoded) != expectedLen {
		return nil, fmt.Errorf("native Groth16 proof bytes have unexpected length")
	}
	proof.Commitments = make([]curve.G1Affine, commitmentCount)
	for i := 0; i < int(commitmentCount); i++ {
		if _, err := proof.Commitments[i].SetBytes(encoded[offset : offset+48]); err != nil {
			return nil, err
		}
		offset += 48
	}
	if _, err := proof.CommitmentPok.SetBytes(encoded[offset : offset+48]); err != nil {
		return nil, err
	}
	return proof, nil
}

func DecodeVerificationKey(encoded []byte) (*groth16bls12381.VerifyingKey, error) {
	if len(encoded) < len(verifyingKeyMagic)+4+48+96+96+96+4 {
		return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
	}
	if string(encoded[:len(verifyingKeyMagic)]) != string(verifyingKeyMagic) {
		return nil, fmt.Errorf("native Groth16 verifying key bytes have invalid magic")
	}

	vk := new(groth16bls12381.VerifyingKey)
	offset := len(verifyingKeyMagic)
	publicInputCount := binary.LittleEndian.Uint32(encoded[offset : offset+4])
	offset += 4

	if _, err := vk.G1.Alpha.SetBytes(encoded[offset : offset+48]); err != nil {
		return nil, err
	}
	offset += 48
	if _, err := vk.G2.Beta.SetBytes(encoded[offset : offset+96]); err != nil {
		return nil, err
	}
	offset += 96
	if _, err := vk.G2.Gamma.SetBytes(encoded[offset : offset+96]); err != nil {
		return nil, err
	}
	offset += 96
	if _, err := vk.G2.Delta.SetBytes(encoded[offset : offset+96]); err != nil {
		return nil, err
	}
	offset += 96

	gammaAbcCount := binary.LittleEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	if gammaAbcCount < publicInputCount+1 {
		return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
	}

	vk.G1.K = make([]curve.G1Affine, gammaAbcCount)
	for i := 0; i < int(gammaAbcCount); i++ {
		if _, err := vk.G1.K[i].SetBytes(encoded[offset : offset+48]); err != nil {
			return nil, err
		}
		offset += 48
	}
	if offset != len(encoded) {
		if len(encoded)-offset < 4 {
			return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
		}
		commitmentCount := binary.LittleEndian.Uint32(encoded[offset : offset+4])
		offset += 4
		if commitmentCount == 0 {
			return nil, fmt.Errorf("native Groth16 verifying key commitment extension is malformed")
		}
		if gammaAbcCount != publicInputCount+commitmentCount+1 {
			return nil, fmt.Errorf("native Groth16 verifying key gamma_abc count does not match public inputs")
		}
		vk.PublicAndCommitmentCommitted = make([][]int, commitmentCount)
		vk.CommitmentKeys = make([]pedersen.VerifyingKey, commitmentCount)
		for i := 0; i < int(commitmentCount); i++ {
			if len(encoded)-offset < 4 {
				return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
			}
			witnessIndexCount := binary.LittleEndian.Uint32(encoded[offset : offset+4])
			offset += 4
			vk.PublicAndCommitmentCommitted[i] = make([]int, witnessIndexCount)
			for j := 0; j < int(witnessIndexCount); j++ {
				if len(encoded)-offset < 4 {
					return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
				}
				vk.PublicAndCommitmentCommitted[i][j] = int(binary.LittleEndian.Uint32(encoded[offset : offset+4]))
				offset += 4
			}
			if len(encoded)-offset < 96+96 {
				return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
			}
			if _, err := vk.CommitmentKeys[i].G.SetBytes(encoded[offset : offset+96]); err != nil {
				return nil, err
			}
			offset += 96
			if _, err := vk.CommitmentKeys[i].GSigmaNeg.SetBytes(encoded[offset : offset+96]); err != nil {
				return nil, err
			}
			offset += 96
		}
	} else if gammaAbcCount != publicInputCount+1 {
		return nil, fmt.Errorf("native Groth16 verifying key gamma_abc count does not match public inputs")
	}
	if offset != len(encoded) {
		return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
	}
	if err := vk.Precompute(); err != nil {
		return nil, err
	}
	return vk, nil
}

func appendUint32LE(dst []byte, value uint32) []byte {
	return append(dst,
		byte(value&0xff),
		byte((value>>8)&0xff),
		byte((value>>16)&0xff),
		byte((value>>24)&0xff),
	)
}
