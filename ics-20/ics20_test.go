package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

const SIZE = 1 << PROF

func Recursiva(merkle [SIZE * 2][32]uints.U8, nodo int, brotherspath [][32]uints.U8, dir []big.Int, inputleafs [SIZE]*big.Int, t *testing.T) error {
	if nodo*2 >= len(merkle) {
		var Asig Merkle
		for i := 0; i < len(brotherspath); i++ {
			for j := 0; j < CANTL; j++ {
				Asig.Path[j][i] = brotherspath[i]
			}
		}
		for i := 0; i < len(dir); i++ {
			for j := 0; j < CANTL; j++ {
				Asig.PathDirecc[j][i] = dir[i]
			}
		}
		Asig.Root = merkle[1]
		for j := 0; j < CANTL; j++ {
			Asig.Leafq[j] = bytetouint(getBytes(inputleafs[nodo-len(merkle)/2]))
		}
		var circuit Merkle
		assert := test.NewAssert(t)
		err := test.IsSolved(&circuit, &Asig, ecc.BN254.ScalarField())
		assert.NoError(err)
		return nil
	}
	Recursiva(merkle, nodo*2, append(brotherspath, merkle[nodo*2+1]), append(dir, *big.NewInt(0)), inputleafs, t)
	Recursiva(merkle, nodo*2+1, append(brotherspath, merkle[nodo*2]), append(dir, *big.NewInt(1)), inputleafs, t)
	return nil
}

func getBytes(b *big.Int) []byte {
	const SIZE = 32
	bElement := fr.NewElement(b.Uint64())
	res := make([]byte, SIZE)
	for i := 0; i < SIZE; i++ {
		res[i] = bElement.Bytes()[i]
	}
	return res
}

func nodeSumByte(izq []byte, der []byte) []byte {
	sha2 := sha256.New()
	sha2.Write(izq)
	sha2.Write(der)
	return sha2.Sum(make([]byte, 0))
}

func Test(t *testing.T) {
	for nt := 0; nt < 1000; nt++ {
		var Merkle [SIZE * 2][32]uints.U8
		var MerkleBytes [SIZE * 2][]byte
		var inputleafs [SIZE]*big.Int
		for i := 0; i < SIZE; i++ {
			inputleafs[i] = big.NewInt(rand.Int63n(int64(1e18)))
			MerkleBytes[i+SIZE] = getBytes(inputleafs[i])
			Merkle[i+SIZE] = bytetouint(MerkleBytes[i+SIZE])
		}
		for i := SIZE - 1; i > 0; i-- {
			MerkleBytes[i] = nodeSumByte(MerkleBytes[i*2], MerkleBytes[i*2+1])
			Merkle[i] = bytetouint(MerkleBytes[i])
		}

		Recursiva(Merkle, 1, make([][32]uints.U8, 0), []big.Int{}, inputleafs, t)
	}
}

func bytetouint(MerkleBytes []byte) [32]uints.U8 {
	aux := uints.NewU8Array(MerkleBytes)
	var Merkleaux [32]uints.U8
	for j := 0; j < min(32, len(aux)); j++ {
		Merkleaux[j] = aux[j]
	}
	return Merkleaux
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
