module NLitecoin.MimbleWimble.ZKPTests

// Differential tests for zero-knowledge proof components that use https://github.com/tangramproject/Secp256k1-ZKP.Net as reference

open NUnit.Framework
open FsCheck
open FsCheck.NUnit

open NLitecoin.MimbleWimble


type ByteArray32Generators =
    static member ByteArray() =
        { new Arbitrary<array<byte>>() with
            override _.Generator =
                Gen.listOfLength 32 (Gen.choose(0, 255) |> Gen.map byte)
                |> Gen.map List.toArray }

[<Ignore("Unable to find an entry point named 'secp256k1_schnorrsig_sign' in DLL 'libsecp256k1'")>]
[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestSchnorrSign (message: array<byte>) (key: array<byte>) =
    use secp256k1Schnorr = new Secp256k1ZKP.Net.Schnorr()
    (EC.SchnorrSign key message).ToBytes() = secp256k1Schnorr.Sign(message, key)

[<Property(Arbitrary=[|typeof<ByteArray32Generators>|])>]
let TestPedersenCommit (value: CAmount) (blind: array<byte>) =
    use pedersen = new Secp256k1ZKP.Net.Pedersen()
    let referenceBlind = pedersen.BlinCommit(System.BitConverter.GetBytes value, blind)
    let ourBlind = Pedersen.Commit value (BlindingFactor.BlindindgFactor (NBitcoin.uint256 blind))
    ourBlind = (PedersenCommitment(BigInt referenceBlind))