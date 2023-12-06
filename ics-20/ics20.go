package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const CANTL = 10 // amount of leafs also corresponds to amount of packets
const PROF = 5   // depth of tree

type Merkle struct { //circuit that represent merkle tree. the output is the proof of that all leafs belongs to the tree
	Root                 [32]uints.U8                   `gnark:",public"`  // Root of my merkle tree
	AggregatedPacketHash [32]uints.U8                   `gnark:",public"`  //Public hash
	AggregatedPacket     []uints.U8                     `gnark:",private"` //Packet
	Path                 [CANTL][PROF][32]uints.U8      `gnark:",private"` // Path
	PathDirecc           [CANTL][PROF]frontend.Variable `gnark:",private"` //If the leaf is on the left, the value is 0, either, is 1
	Leafq                [CANTL][32]uints.U8            `gnark:",private"` // Leaf
}

func nodeSum(api frontend.API, izq, der [32]uints.U8) [32]uints.U8 {
	h, _ := sha2.New(api)
	h.Write(izq[:])
	h.Write(der[:])
	newn := h.Sum()
	var res [32]uints.U8
	for i := 0; i < 32; i++ {
		res[i] = newn[i]
	}
	return res
}

func (circuit *Merkle) Define(api frontend.API) error {
	var hash2 [32]uints.U8

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	for j := 0; j < CANTL; j++ {
		hash2 = circuit.Leafq[j]
		for i := PROF - 1; i >= 0; i-- {
			a := nodeSum(api, circuit.Path[j][i], hash2)
			b := nodeSum(api, hash2, circuit.Path[j][i])
			for k := 0; k < 32; k++ {
				hash2[k] = uapi.ByteValueOf(api.Select(circuit.PathDirecc[j][i], a[k].Val, b[k].Val))
			}
		}
		for k := range circuit.Root {
			uapi.ByteAssertEq(circuit.Root[k], hash2[k])
		}
	}
	return nil
}

func (circuit *Merkle) Definee(api frontend.API) error {
	hpacket, err := sha2.New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	hpacket.Write(circuit.AggregatedPacket)
	res := hpacket.Sum()
	for i := range circuit.AggregatedPacketHash {
		uapi.ByteAssertEq(circuit.AggregatedPacketHash[i], res[i])
	}
	return nil
}

func (circuit *Circuit) Define(api frontend.API) error {
	h := api.Add(circuit.X, circuit.Y)
	api.AssertIsEqual("38", h)
	return nil
}

type Circuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func main() {
	//var myCircuit Merkle
	//cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	//_, vk, _ := groth16.Setup(cs)
	//f, _ := os.Create("contract_g16.sol")
	//vk.ExportSolidity(f)
	//assignment := &Merkle {
	//	Root: 3,
	//	AggregatedPacketHash: ,
	//	AggregatedPacket: ,
	//	Path: ,
	//	PathDirecc: ,
	//	Leafq: ,

	assignment := &Circuit{
		X: 3,
		Y: 35,
	}
	var myCircuit Circuit
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	pk, _, _ := groth16.Setup(cs)
	proof, _ := groth16.Prove(cs, pk, witness)
	fmt.Print(proof)

}
