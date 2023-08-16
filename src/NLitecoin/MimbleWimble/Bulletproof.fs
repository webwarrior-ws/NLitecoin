module NLitecoin.MimbleWimble.Bulletproof

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Security
open Org.BouncyCastle.Asn1.X9
open Org.BouncyCastle.Math
open NBitcoin

// should be equivalent to https://github.com/litecoin-project/litecoin/blob/master/src/secp256k1-zkp/src/field_impl.h#L290
let IsQuadVar (elem: EC.ECFieldElement) =
    elem.Sqrt().Square() = elem

let UpdateCommit (commit: uint256) (lpt: EC.ECPoint) (rpt: EC.ECPoint) : uint256 =
    let lparity = 
        (if IsQuadVar lpt.AffineYCoord then 0uy else 2uy) 
        + (if IsQuadVar rpt.AffineYCoord then 0uy else 1uy)

    let hasher = Sha256Digest()
    hasher.BlockUpdate(commit.ToBytes(), 0, 32)
    hasher.Update lparity
    hasher.BlockUpdate(lpt.AffineXCoord.GetEncoded(), 0, 32)
    hasher.BlockUpdate(rpt.AffineXCoord.GetEncoded(), 0, 32)
    
    let result = Array.zeroCreate<byte> 32
    hasher.DoFinal(result, 0) |> ignore
    result |> uint256

let ConstructRangeProof (amount: uint64) (key: uint256) (privateNonce: uint256) (rewindNonce: uint256) (proofMessage: array<byte>) (extraData: array<byte>) : RangeProof =
    let commitp = 
        Pedersen.generatorH.Multiply(BigInteger.ValueOf(int64 amount))
            .Add(Pedersen.generatorG.Multiply(key.ToBytes() |> BigInteger))

    let commit = UpdateCommit uint256.Zero commitp Pedersen.generatorH

    let commit = 
        let hasher = Sha256Digest()
        hasher.BlockUpdate(commit.ToBytes(), 0, 32)
        hasher.BlockUpdate(extraData, 0, extraData.Length)
        let result = Array.zeroCreate<byte> 32
        hasher.DoFinal(result, 0) |> ignore
        result

    // following values are meant to be random in the Bulletproof paper, but in secp256k1-zkp
    // they are generated from privateNonce and rewindNonce and alpha is meant to be recoverable
    // (see https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/modules/bulletproofs/rangeproof_impl.h#L526)
    let random = SecureRandom()
    let alpha = Pedersen.curve.Curve.RandomFieldElement random
    let rho = Pedersen.curve.Curve.RandomFieldElement random
    let tau1 = Pedersen.curve.Curve.RandomFieldElement random
    let tau2 = Pedersen.curve.Curve.RandomFieldElement random
    
    failwith "not implemented"
