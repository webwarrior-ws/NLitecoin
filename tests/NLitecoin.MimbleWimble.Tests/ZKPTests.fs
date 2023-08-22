module NLitecoin.MimbleWimble.ZKPTests

// Differential tests for zero-knowledge proof components that use https://github.com/tangramproject/Secp256k1-ZKP.Net as reference

open NUnit.Framework
open FsCheck
open FsCheck.NUnit

open NLitecoin.MimbleWimble
open NLitecoin.MimbleWimble.EC

type ByteArray32Generators =
    static member ByteArray() =
        { new Arbitrary<array<byte>>() with
            override _.Generator =
                Gen.listOfLength 32 (Gen.choose(0, 255) |> Gen.map byte)
                |> Gen.map List.toArray }
    
    static member BlindingFactor() =
        { new Arbitrary<BlindingFactor>() with
            override _.Generator =
                Arb.generate<array<byte>>
                |> Gen.map NBitcoin.uint256
                |> Gen.map BlindingFactor.BlindingFactor }

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
let TestBlindingFactor (factor: BlindingFactor) =
    let bytes = factor.ToUInt256().ToBytes()
    (bytes |> Org.BouncyCastle.Math.BigInteger.FromByteArrayUnsigned |> EC.curve.Curve.FromBigInteger).GetEncoded() = bytes

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestBigIntegerToUInt256 (bytes: array<byte>) =
    let integer = bytes |> Org.BouncyCastle.Math.BigInteger.FromByteArrayUnsigned
    integer = (integer.ToUInt256().ToBytes() |> Org.BouncyCastle.Math.BigInteger.FromByteArrayUnsigned)