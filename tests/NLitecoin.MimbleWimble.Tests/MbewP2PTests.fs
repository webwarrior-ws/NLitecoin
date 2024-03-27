module NLitecoin.MimbleWimble.MbewP2PTests

open FsCheck
open FsCheck.NUnit

open NBitcoin
open NBitcoin.Protocol

open NLitecoin.MimbleWimble
open NLitecoin.MimbleWimble.MwebP2P

type Generators =
    inherit SerializationTests.Generators
    
    static member BitArray() =
        { new Arbitrary<System.Collections.BitArray>() with
            override _.Generator =
                gen {
                    let! numBits = Gen.choose(8, 8)
                    let! bits = Gen.listOfLength numBits (Gen.elements [| true; false |])
                    return bits |> List.toArray |> System.Collections.BitArray
                } }

    static member CompactUtxo() =
        { new Arbitrary<CompactUtxo>() with
            override _.Generator =
                gen {
                    let! leafIndex = Arb.generate<uint64>
                    let! output = Arb.generate<Output>
                    let hash = Hasher.CalculateHash output.RangeProof
                    return { CompactUtxo.LeafIndex = leafIndex; Output = { output with RangeProof = RangeProof(hash.ToBytes()) } }
                } }

[<Property(Arbitrary=[|typeof<Generators>|])>]
let MwebLeafsetSerializationRoundtrip (leafset: MwebLeafset) =
    SerializationTests.roundtripObject leafset MwebLeafset.Read

[<Property(Arbitrary=[|typeof<Generators>|])>]
let MwebUtxosRequestSerializationRoundtrip (request: MwebUtxosRequest) =
    SerializationTests.roundtripObject request MwebUtxosRequest.Read

[<Property(Arbitrary=[|typeof<Generators>|])>]
let FullMwebUtxosSerializationRoundtrip (utxos: MwebUtxos<FullUtxo>) =
    let readerFunc (stream: BitcoinStream) =
        let blockHash = ReadUint256 stream
        let startIndex = VarInt.StaticRead stream
        stream.ReadWrite 0uy |> ignore
        MwebUtxos<FullUtxo>.Read stream FullUtxo.Read blockHash startIndex
    SerializationTests.roundtripObject utxos readerFunc

[<Property(Arbitrary=[|typeof<Generators>|])>]
let CompactMwebUtxosSerializationRoundtrip (utxos: MwebUtxos<CompactUtxo>) =
    let readerFunc (stream: BitcoinStream) =
        let blockHash = ReadUint256 stream
        let startIndex = VarInt.StaticRead stream
        stream.ReadWrite 0uy |> ignore
        MwebUtxos<CompactUtxo>.Read stream CompactUtxo.Read blockHash startIndex
    SerializationTests.roundtripObject utxos readerFunc

[<Property(Arbitrary=[|typeof<Generators>|])>]
let HashOnlyMwebUtxosSerializationRoundtrip (utxos: MwebUtxos<HashOnlyUtxo>) =
    let readerFunc (stream: BitcoinStream) =
        let blockHash = ReadUint256 stream
        let startIndex = VarInt.StaticRead stream
        stream.ReadWrite 0uy |> ignore
        MwebUtxos<HashOnlyUtxo>.Read stream HashOnlyUtxo.Read blockHash startIndex
    SerializationTests.roundtripObject utxos readerFunc
