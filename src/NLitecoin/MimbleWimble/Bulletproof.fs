module NLitecoin.MimbleWimble.Bulletproof

open System

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Security
open Org.BouncyCastle.Math
open Org.BouncyCastle.Math.EC
open NBitcoin

let ScalarCheckOverflow (a: array<uint64>) : bool =
    let SECP256K1_N_0 = 0xBFD25E8CD0364141UL
    let SECP256K1_N_1 = 0xBAAEDCE6AF48A03BUL
    let SECP256K1_N_2 = 0xFFFFFFFFFFFFFFFEUL
    let SECP256K1_N_3 = 0xFFFFFFFFFFFFFFFFUL

    let mutable yes = false
    let mutable no = false
    no <- (a.[3] < SECP256K1_N_3) // No need for a > check.
    no <- no || (a.[2] < SECP256K1_N_2)
    yes <- yes || (a.[2] > SECP256K1_N_2) && not no
    no <- no || (a.[1] < SECP256K1_N_1)
    yes <- yes || (a.[1] > SECP256K1_N_1) && not no
    yes <- yes || (a.[0] >= SECP256K1_N_0) && not no
    yes

// port of https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/scalar.h#L114
let ScalarChaCha20 (seed: uint256) (index: uint64) : ECFieldElement * ECFieldElement =
    let mutable overCount = 0
    let seed32 = seed.ToBytes() |> Array.chunkBySize 4 |> Array.map BitConverter.ToUInt32
    let mutable x = Array.zeroCreate<uint32> 16
    let mutable r1 = Array.empty
    let mutable r2 = Array.empty
    let mutable overCount = 0u
    let mutable over1 = true
    let mutable over2 = true

    let inline LE32 p =
        if BitConverter.IsLittleEndian then
            p
        else
            ((p &&& 0xFFu) <<< 24) ||| ((p &&& 0xFF00u) <<< 8) ||| (((p) &&& 0xFF0000u) >>> 8) ||| (((p) &&& 0xFF000000u) >>> 24)

    let inline BE32 p =
        if BitConverter.IsLittleEndian then
            ((p &&& 0xFFUL) <<< 24) ||| ((p &&& 0xFF00UL) <<< 8) ||| ((p &&& 0xFF0000UL) >>> 8) ||| ((p &&& 0xFF000000UL) >>> 24)
        else
            p

    let ROTL32(x, n) = ((x) <<< (n) ||| (x) >>> (32-(n)))

    let QUARTERROUND (a,b,c,d) = 
        x.[a] <- x.[a] + x.[b]
        x.[d] <- ROTL32(x.[d] ^^^ x.[a], 16)
        x.[c] <- x.[c] + x.[d]
        x.[b] <- ROTL32(x.[b] ^^^ x.[c], 12)
        x.[a] <- x.[a] + x.[b]
        x.[d] <- ROTL32(x.[d] ^^^ x.[a], 8)
        x.[c] <- x.[d]
        x.[b] <- ROTL32(x.[b] ^^^ x.[c], 7)

    while (over1 || over2) do
        x <- [|
            0x61707865u
            0x3320646eu
            0x79622d32u
            0x6b206574u
            LE32(seed32.[0])
            LE32(seed32.[1])
            LE32(seed32.[2])
            LE32(seed32.[3])
            LE32(seed32.[4])
            LE32(seed32.[5])
            LE32(seed32.[6])
            LE32(seed32.[7])
            uint32 index
            uint32(index >>> 32)
            0u
            overCount
        |]

        for i=1 to 10 do
            QUARTERROUND(0, 4, 8,12)
            QUARTERROUND(1, 5, 9,13)
            QUARTERROUND(2, 6,10,14)
            QUARTERROUND(3, 7,11,15)
            QUARTERROUND(0, 5,10,15)
            QUARTERROUND(1, 6,11,12)
            QUARTERROUND(2, 7, 8,13)
            QUARTERROUND(3, 4, 9,14)

        x <- 
            Array.map2
                (+)
                x
                [|
                    0x61707865u
                    0x3320646eu
                    0x79622d32u
                    0x6b206574u
                    LE32(seed32[0]);
                    LE32(seed32[1]);
                    LE32(seed32[2]);
                    LE32(seed32[3]);
                    LE32(seed32[4]);
                    LE32(seed32[5]);
                    LE32(seed32[6]);
                    LE32(seed32[7]);
                    uint32 index
                    uint32(index >>> 32)
                    0u
                    overCount
                |]
        r1 <-
            [| 
                BE32(uint64 x.[6]) <<< 32 ||| BE32(uint64 x.[7])
                BE32(uint64 x.[4]) <<< 32 ||| BE32(uint64 x.[5])
                BE32(uint64 x.[2]) <<< 32 ||| BE32(uint64 x.[3])
                BE32(uint64 x.[0]) <<< 32 ||| BE32(uint64 x.[1])
            |]
        r2 <-
            [|
                BE32(uint64 x.[14]) <<< 32 ||| BE32(uint64 x.[15])
                BE32(uint64 x.[12]) <<< 32 ||| BE32(uint64 x.[13])
                BE32(uint64 x.[10]) <<< 32 ||| BE32(uint64 x.[11])
                BE32(uint64 x.[8]) <<< 32 ||| BE32(uint64 x.[9])
            |]

        // maybe ECCurve.IsValidFieldElement will do the job?
        over1 <- ScalarCheckOverflow r1
        over2 <- ScalarCheckOverflow r2

        overCount <- overCount + 1u

    let createFieldElement (arr: array<uint64>) =
        BigInteger(arr |> Array.map BitConverter.GetBytes |> Array.concat)
        |> EC.curve.Curve.FromBigInteger

    createFieldElement r1, createFieldElement r2

let UpdateCommit (commit: uint256) (lpt: ECPoint) (rpt: ECPoint) : uint256 =
    let lparity = 
        (if EC.IsQuadVar lpt.AffineYCoord then 0uy else 2uy) 
        + (if EC.IsQuadVar rpt.AffineYCoord then 0uy else 1uy)

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
        EC.generatorH.Multiply(BigInteger.ValueOf(int64 amount))
            .Add(EC.generatorG.Multiply(key.ToBytes() |> BigInteger))

    let commit = UpdateCommit uint256.Zero commitp EC.generatorH

    let commit = 
        let hasher = Sha256Digest()
        hasher.BlockUpdate(commit.ToBytes(), 0, 32)
        hasher.BlockUpdate(extraData, 0, extraData.Length)
        let result = Array.zeroCreate<byte> 32
        hasher.DoFinal(result, 0) |> ignore
        result

    let random = SecureRandom()
    let alpha, rho = ScalarChaCha20 rewindNonce 0UL
    let tau1, tau2 = ScalarChaCha20 privateNonce 1UL

    // Encrypt value into alpha, so it will be recoverable from -mu by someone who knows rewindNonce
    let alpha = 
        let vals = BigInteger.ValueOf(int64 amount) |> EC.curve.Curve.FromBigInteger
        // Combine value with 20 bytes of optional message
        let vals_bytes = vals.GetEncoded()
        for i=0 to 20-1 do
            vals_bytes.[i+4] <- proofMessage.[i]
        let vals = BigInteger vals_bytes |> EC.curve.Curve.FromBigInteger
        // Negate so it'll be positive in -mu
        let vals = vals.Negate()
        alpha.Add vals

    let nbits = 64

    // Compute A and S
    let aL = Array.init nbits (fun i -> amount &&& uint64(1UL <<< i))
    let aR = aL |> Array.map (fun n -> 1UL - n)
        
    
    failwith "not implemented"
