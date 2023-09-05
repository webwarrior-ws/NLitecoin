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

    [<DllImport("libsecp256k1", CallingConvention = CallingConvention.Cdecl)>]
    static extern int secp256k1_generator_generate(nativeint ctx, IntPtr gen, byte[] key32)

    [<DllImport("libsecp256k1", CallingConvention = CallingConvention.Cdecl)>]
    static extern int secp256k1_generator_serialize(nativeint ctx, byte[] output, IntPtr gen)

    member self.InnerproductProofLength(n: uint64) : uint64 =
        secp256k1_bulletproof_innerproduct_proof_length(n)

    member self.GeneratorGenerate(key: array<byte>) =
        let gen = Marshal.AllocHGlobal 64
        let opResult = secp256k1_generator_generate(self.Context, gen, key)
        assert(opResult <> 0)
        assert(gen <> IntPtr.Zero)
        let output = Array.zeroCreate<byte> 33
        let opResult2 = secp256k1_generator_serialize(self.Context, output, gen)
        assert(opResult2 <> 0)
        Marshal.FreeHGlobal gen
        output

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

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestGeneratorGenerate(key: array<byte>) =
    use secp256k1ZKPBulletProof = new Secp256k1ZKpBulletproof()
    let referenceGenerator = secp256k1ZKPBulletProof.GeneratorGenerate key
    
    let ourGenerator = Bulletproof.GeneratorGenerate key
    let ourGeneratorSerialized = ourGenerator.GetEncoded true
    
    // skip first byte since serialization formats are different
    referenceGenerator.[1..] = ourGeneratorSerialized.[1..]

[<Test>]
let TestRfc6979HmacSha256() =
    // output from modified secp256k1-zkp tests
    // first 2 keys generated in secp256k1_bulletproof_generators_create
    // from generatorG as seed
    let referenceKeys =
        [| 
            "edc883a98f9ad8dad390a2c814647b6dac92aed530da554db914ea4f8ad988c7"
            "d99994e5535e0788752493113103145529e20b38e1c68dc28f67816b2a85b65f"
        |]
        |> Array.map(fun str -> Convert.FromHexString str)

    let ourKeys =
        let seed = Array.append (generatorG.XCoord.GetEncoded()) (generatorG.YCoord.GetEncoded())
        let rng = Bulletproof.Rfc6979HmacSha256 seed
        Array.init 2 (fun _ -> rng.Generate 32)

    Array.iter2 
        (fun refKey ourKey -> Assert.AreEqual(refKey, ourKey))
        referenceKeys
        ourKeys
