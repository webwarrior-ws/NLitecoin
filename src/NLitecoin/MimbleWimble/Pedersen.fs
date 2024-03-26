﻿module NLitecoin.MimbleWimble.Pedersen

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Asn1.X9
open Org.BouncyCastle.Math
open NBitcoin


let curve = ECNamedCurveTable.GetByName("secp256k1")
let domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed())

let generatorG = curve.G
let generatorH = 
    curve.Curve.CreatePoint
        (BigInteger 
            [| 0x50uy; 0x92uy; 0x9buy; 0x74uy; 0xc1uy; 0xa0uy; 0x49uy; 0x54uy; 0xb7uy; 0x8buy; 0x4buy; 0x60uy; 0x35uy; 0xe9uy; 0x7auy; 0x5euy;
               0x07uy; 0x8auy; 0x5auy; 0x0fuy; 0x28uy; 0xecuy; 0x96uy; 0xd5uy; 0x47uy; 0xbfuy; 0xeeuy; 0x9auy; 0xceuy; 0x80uy; 0x3auy; 0xc0uy; |],
         BigInteger
            [| 0x31uy; 0xd3uy; 0xc6uy; 0x86uy; 0x39uy; 0x73uy; 0x92uy; 0x6euy; 0x04uy; 0x9euy; 0x63uy; 0x7cuy; 0xb1uy; 0xb5uy; 0xf4uy; 0x0auy;
               0x36uy; 0xdauy; 0xc2uy; 0x8auy; 0xf1uy; 0x76uy; 0x69uy; 0x68uy; 0xc3uy; 0x0cuy; 0x23uy; 0x13uy; 0xf3uy; 0xa3uy; 0x89uy; 0x04uy; |])

let generatorJPub = 
    curve.Curve.CreatePoint
        (BigInteger 
            [|
                0x5fuy; 0x15uy; 0x21uy; 0x36uy; 0x93uy; 0x93uy; 0x01uy; 0x2auy; 0x8duy; 0x8buy; 0x39uy; 0x7euy; 0x9buy; 0xf4uy; 0x54uy; 0x29uy;
                0x2fuy; 0x5auy; 0x1buy; 0x3duy; 0x38uy; 0x85uy; 0x16uy; 0xc2uy; 0xf3uy; 0x03uy; 0xfcuy; 0x95uy; 0x67uy; 0xf5uy; 0x60uy; 0xb8uy; |],
         BigInteger 
            [|
                0x3auy; 0xc4uy; 0xc5uy; 0xa6uy; 0xdcuy; 0xa2uy; 0x01uy; 0x59uy; 0xfcuy; 0x56uy; 0xcfuy; 0x74uy; 0x9auy; 0xa6uy; 0xa5uy; 0x65uy;
                0x31uy; 0x6auy; 0xa5uy; 0x03uy; 0x74uy; 0x42uy; 0x3fuy; 0x42uy; 0x53uy; 0x8fuy; 0xaauy; 0x2cuy; 0xd3uy; 0x09uy; 0x3fuy; 0xa4uy; |]) 

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
        generatorG.Multiply(blind.ToUInt256().ToBytes() |> BigInteger)
            .Add(generatorH.Multiply(BigInteger.ValueOf value))
    let bytes = result.GetEncoded()
    assert(bytes.Length = PedersenCommitment.NumBytes)
    PedersenCommitment(BigInt bytes)

let AddBlindingFactors (positive: array<BlindingFactor>) (negative: array<BlindingFactor>) : BlindingFactor =
    let sum (factors: array<BlindingFactor>) = 
        factors
        |> Array.map (fun blind -> blind.ToUInt256().ToBytes() |> BigInteger)
        |> Array.fold (fun (a : BigInteger) b -> a.Add(b)) BigInteger.Zero
    
    let result = (sum positive).Subtract(sum negative)
    
    result.ToByteArrayUnsigned()
    |> uint256
    |> BlindingFactor.BlindingFactor
