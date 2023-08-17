module NLitecoin.MimbleWimble.Pedersen

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Asn1.X9
open Org.BouncyCastle.Math
open NBitcoin

open EC

/// Calculates the blinding factor x' = x + SHA256(xG+vH | xJ), used in the switch commitment x'G+vH.
let BlindSwitch (blindingFactor: BlindingFactor) (amount: CAmount) : BlindingFactor =
    let hasher = Sha256Digest()

    let x = blindingFactor.ToUint256().ToBytes() |> BigInteger
    let v = amount.ToString() |> BigInteger
    /// xG + vH
    let commitSerialized = generatorG.Multiply(x).Add(generatorH.Multiply(v)).GetEncoded()
    hasher.BlockUpdate(commitSerialized, 0, commitSerialized.Length)

    // xJ
    let xJ = generatorJPub.Multiply x
    let xJSerialized = xJ.GetEncoded true
    hasher.BlockUpdate(xJSerialized, 0, xJSerialized.Length)

    let hash = Array.zeroCreate<byte> 32
    hasher.DoFinal(hash, 0) |> ignore

    let result = x.Add(BigInteger hash)

    result.ToByteArrayUnsigned() 
    |> uint256 
    |> BlindingFactor.BlindindgFactor

/// Generates a pedersen commitment: *commit = blind * G + value * H. The blinding factor is 32 bytes.
let Commit (value: CAmount) (blind: BlindingFactor) : PedersenCommitment =
    let result =
        generatorG.Multiply(blind.ToUint256().ToBytes() |> BigInteger)
            .Add(generatorH.Multiply(BigInteger.ValueOf value))
    let bytes = result.GetEncoded(true)
    assert(bytes.Length = PedersenCommitment.NumBytes)
    PedersenCommitment(BigInt bytes)

let AddBlindingFactors (positive: array<BlindingFactor>) (negative: array<BlindingFactor>) : BlindingFactor =
    let sum (factors: array<BlindingFactor>) = 
        factors
        |> Array.map (fun blind -> blind.ToUint256().ToBytes() |> BigInteger)
        |> Array.fold (fun (a : BigInteger) b -> a.Add(b)) BigInteger.Zero
    
    let result = (sum positive).Subtract(sum negative)
    
    result.ToByteArrayUnsigned()
    |> uint256
    |> BlindingFactor.BlindindgFactor
