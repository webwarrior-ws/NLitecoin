module NLitecoin.MimbleWimble.ZKPTests

// Differential tests for zero-knowledge proof components that use https://github.com/tangramproject/Secp256k1-ZKP.Net as reference

open System
open System.Runtime.InteropServices

open NUnit.Framework
open FsCheck
open FsCheck.NUnit
open Org.BouncyCastle.Math
open NBitcoin

open NLitecoin.MimbleWimble
open NLitecoin.MimbleWimble.EC

type ByteArray32Generators =
    static member ByteArray() =
        { new Arbitrary<array<byte>>() with
            override _.Generator =
                Gen.arrayOfLength 32 (Gen.choose(0, 255) |> Gen.map byte)  }

    static member UInt256() =
        { new Arbitrary<uint256>() with
            override _.Generator =
                Arb.generate<array<byte>> |> Gen.map uint256  }
    
    static member BlindingFactor() =
        { new Arbitrary<BlindingFactor>() with
            override _.Generator =
                gen {
                    let! bytes = Arb.generate<array<byte>>
                    let! leadingZeros = Gen.elements [ 0; 0; 0; 1; 31 ]
                    Array.fill bytes 0 leadingZeros 0uy
                    return bytes |> NBitcoin.uint256 |> BlindingFactor } }

type private Secp256k1ZKpBulletproof() =
    inherit Secp256k1ZKP.Net.BulletProof()

    [<DllImport("libsecp256k1", CallingConvention = CallingConvention.Cdecl)>]
    static extern uint64 secp256k1_bulletproof_innerproduct_proof_length(uint64 n)

    member self.InnerproductProofLength(n: uint64) : uint64 =
        secp256k1_bulletproof_innerproduct_proof_length(n)

[<Ignore("Unable to find an entry point named 'secp256k1_schnorrsig_sign' in DLL 'libsecp256k1'")>]
[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestSchnorrSign (message: array<byte>) (key: array<byte>) =
    use secp256k1Schnorr = new Secp256k1ZKP.Net.Schnorr()
    (EC.SchnorrSign key message).ToBytes() = secp256k1Schnorr.Sign(message, key)

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestPedersenCommit (value: uint64) (blind: BlindingFactor) =
    use pedersen = new Secp256k1ZKP.Net.Pedersen()
    let referenceCommitment = pedersen.Commit(value, blind.ToUInt256().ToBytes())
    let ourCommitment = Pedersen.Commit (int64 value) blind
    ourCommitment = (PedersenCommitment(BigInt referenceCommitment))

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestBlindSwitch (value: uint64) (blind: BlindingFactor) =
    use pedersen = new Secp256k1ZKP.Net.Pedersen()
    let referenceBlind = pedersen.BlindSwitch(value, blind.ToUInt256().ToBytes())
    let ourBlind = Pedersen.BlindSwitch blind (int64 value)
    ourBlind = (BlindingFactor(uint256 referenceBlind))

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestBlindingFactor (factor: BlindingFactor) =
    let bytes = factor.ToUInt256().ToBytes()
    (bytes |> BigInteger.FromByteArrayUnsigned |> EC.curve.Curve.FromBigInteger).GetEncoded() = bytes

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestBigIntegerToUInt256 (bytes: array<byte>) =
    let integer = bytes |> BigInteger.FromByteArrayUnsigned
    integer = (integer.ToUInt256().ToBytes() |> Org.BouncyCastle.Math.BigInteger.FromByteArrayUnsigned)

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestAddBlindingFactors (positive: array<BlindingFactor>) (negative: array<BlindingFactor>) =
    use pedersen = new Secp256k1ZKP.Net.Pedersen()
    let referenceSum = 
        pedersen.BlindSum(
            positive |> Array.map (fun each -> each.ToUInt256().ToBytes()),
            negative |> Array.map (fun each -> each.ToUInt256().ToBytes())
        )
    let ourSum = Pedersen.AddBlindingFactors positive negative
    ourSum.ToUInt256().ToBytes() = referenceSum

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestRangeProofCanBeVerified 
    (amount: uint64) 
    (key: uint256) 
    (privateNonce: uint256) 
    (rewindNonce: uint256) =
    let commit = 
        match Pedersen.Commit (int64 amount) (BlindingFactor <| key) with
        | PedersenCommitment num -> num.Data
    let extraData = Array.empty

    let proofMessage = Array.zeroCreate RangeProof.Size
    let proof = Bulletproof.ConstructRangeProof amount key privateNonce rewindNonce proofMessage extraData
    let proofData = 
        match proof with
        | RangeProof data -> data
    
    use secp256k1ZKPBulletProof = new Secp256k1ZKpBulletproof()
    //let proofMessageZKP = secp256k1ZKPBulletProof.ProofSingle(amount, key.ToBytes(), privateNonce.ToBytes(), rewindNonce.ToBytes(), extraData, [||])

    secp256k1ZKPBulletProof.Verify(commit, proofData, extraData)

[<Test>]
let TestInnerproductProofLength() =
    use secp256k1ZKPBulletProof = new Secp256k1ZKpBulletproof()
    for exp=0 to 16 do
        let n = pown 2 (int exp)
        let ourLength = Bulletproof.InnerProductProofLength(int n)
        let referenceLength = secp256k1ZKPBulletProof.InnerproductProofLength(uint64 n)
        Assert.AreEqual(referenceLength, uint64 ourLength)
