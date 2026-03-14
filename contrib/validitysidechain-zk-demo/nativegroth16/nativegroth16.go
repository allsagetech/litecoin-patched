package nativegroth16

import (
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

func EncodeProof(proof *groth16bls12381.Proof) []byte {
	out := []byte{'V', 'S', 'G', 'P', 0x01}
	a := proof.Ar.Bytes()
	b := proof.Bs.Bytes()
	c := proof.Krs.Bytes()
	out = append(out, a[:]...)
	out = append(out, b[:]...)
	out = append(out, c[:]...)
	return out
}

func EncodeVerificationKey(vk *groth16bls12381.VerifyingKey) []byte {
	out := []byte{'V', 'S', 'G', 'V', 'K', 0x01}
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

func appendUint32LE(dst []byte, value uint32) []byte {
	return append(dst,
		byte(value&0xff),
		byte((value>>8)&0xff),
		byte((value>>16)&0xff),
		byte((value>>24)&0xff),
	)
}
