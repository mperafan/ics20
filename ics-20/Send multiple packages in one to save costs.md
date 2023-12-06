## Send multiple packages in one to save costs

The idea of the project was to create a merkle tree to be able to send several packages in one. In this way we would reduce costs.

### Let's start!

We have three constants.

```
const CANTL = 10 // amount of leafs also corresponds to amount of packets

const PROF = 5   // depth of tree
```

And we have a structure that represents the merkle tree.

```
type Merkle struct { //circuit that represent merkle tree. the output is the proof of that all leafs belongs to the tree

​    Root                 [32]uints.U8                   `gnark:",public"` 
// Root of my merkle tree

​    AggregatedPacketHash [32]uints.U8                   `gnark:",public"`  //Public hash

​    AggregatedPacket     []uints.U8                     `gnark:",private"` //Packet

​    Path                 [CANTL][PROF][32]uints.U8      `gnark:",private"`
// Path

​    PathDirecc           [CANTL][PROF]frontend.Variable `gnark:",private"`
//If the leaf is on the left, the value is 0, either, is 1

​    Leafq                [CANTL][32]uints.U8            `gnark:",private"`
// Leaf

}
```

And then, we have the functions.

This function returns the hash of the parent of two nodes.

```
func nodeSum(api frontend.API, izq, der [32]uints.U8) [32]uints.U8 {

​    h, _ := sha2.New(api)

​    h.Write(izq[:])

​    h.Write(der[:])

​    newn := h.Sum()

​    var res [32]uints.U8

​    for i := 0; i < 32; i++ {

​        res[i] = newn[i]

​    }

​    return res

}
```

This function verifies that all leaves belong to the tree.

```
func (circuit *Merkle) Define(api frontend.API) error {

​    var hash2 [32]uints.U8

​    uapi, err := uints.New[uints.U32](api)

​    if err != nil {

​        return err

​    }

​    for j := 0; j < CANTL; j++ {

​        hash2 = circuit.Leafq[j]

​        for i := PROF - 1; i >= 0; i-- {

​            a := nodeSum(api, circuit.Path[j][i], hash2)

​            b := nodeSum(api, hash2, circuit.Path[j][i])

​            for k := 0; k < 32; k++ {

​                hash2[k] = uapi.ByteValueOf(api.Select(circuit.PathDirecc[j][i], a[k].Val, b[k].Val))

​            }

​        }

​        for k := range circuit.Root {

​            uapi.ByteAssertEq(circuit.Root[k], hash2[k])

​        }

​    }

​    return nil

}
```

