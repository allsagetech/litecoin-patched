package nativegroth16

import (
	"encoding/binary"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

var proofMagic = []byte{'V', 'S', 'G', 'P', 0x01}
var verifyingKeyMagic = []byte{'V', 'S', 'G', 'V', 'K', 0x01}

func EncodeProof(proof *groth16bls12381.Proof) []byte {
	out := append([]byte{}, proofMagic...)
	a := proof.Ar.Bytes()
	b := proof.Bs.Bytes()
	c := proof.Krs.Bytes()
	out = append(out, a[:]...)
	out = append(out, b[:]...)
	out = append(out, c[:]...)
	return out
}

func EncodeVerificationKey(vk *groth16bls12381.VerifyingKey) []byte {
	out := append([]byte{}, verifyingKeyMagic...)
	out = appendUint32LE(out, uint32(len(vk.G1.K)-1))
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
	return out
}

func DecodeProof(encoded []byte) (*groth16bls12381.Proof, error) {
	const expectedLen = 5 + 48 + 96 + 48
	if len(encoded) != expectedLen {
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
	if gammaAbcCount != publicInputCount+1 {
		return nil, fmt.Errorf("native Groth16 verifying key gamma_abc count does not match public inputs")
	}
	expectedLen := offset + int(gammaAbcCount)*48
	if len(encoded) != expectedLen {
		return nil, fmt.Errorf("native Groth16 verifying key bytes have unexpected length")
	}

	vk.G1.K = make([]curve.G1Affine, gammaAbcCount)
	for i := 0; i < int(gammaAbcCount); i++ {
		if _, err := vk.G1.K[i].SetBytes(encoded[offset : offset+48]); err != nil {
			return nil, err
		}
		offset += 48
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
