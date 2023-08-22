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

    let x = blindingFactor.ToUInt256().ToBytes() |> BigInteger
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
    |> BlindingFactor.BlindingFactor

/// Generates a pedersen commitment: *commit = blind * G + value * H. The blinding factor is 32 bytes.
let Commit (value: CAmount) (blind: BlindingFactor) : PedersenCommitment =
    let result =
        let blind = blind.ToUInt256().ToBytes() |> BigInteger.FromByteArrayUnsigned
        let a = generatorG.Multiply(blind)
        let b = generatorH.Multiply(BigInteger.ValueOf value)
        a.Add b
    let bytes = result.GetEncoded true
    // https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/modules/commitment/main_impl.h#L41
    bytes.[0] <- 9uy ^^^ (if EC.IsQuadVar (result.Normalize().YCoord) then 1uy else 0uy)
    assert(bytes.Length = PedersenCommitment.NumBytes)
    PedersenCommitment(BigInt bytes)

let AddBlindingFactors (positive: array<BlindingFactor>) (negative: array<BlindingFactor>) : BlindingFactor =
    let sum (factors: array<BlindingFactor>) = 
        factors
        |> Array.map (fun blind -> blind.ToUInt256().ToBytes() |> BigInteger.FromByteArrayUnsigned |> curve.Curve.FromBigInteger)
        |> Array.fold (fun (a : ECFieldElement) b -> a.Add b) (curve.Curve.FromBigInteger BigInteger.Zero)
    
    let result = (sum positive).Subtract(sum negative)
    
    result.ToBigInteger().ToUInt256()
    |> uint256
    |> BlindingFactor.BlindingFactor
