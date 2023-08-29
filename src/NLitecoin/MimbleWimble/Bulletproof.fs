module NLitecoin.MimbleWimble.Bulletproof

open System

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Security
open Org.BouncyCastle.Math
open Org.BouncyCastle.Math.EC
open NBitcoin

open EC

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
let ScalarChaCha20 (seed: uint256) (index: uint64) : BigInteger * BigInteger =
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

        over1 <- ScalarCheckOverflow r1
        over2 <- ScalarCheckOverflow r2

        overCount <- overCount + 1u

    let createScalar (arr: array<uint64>) =
        BigInteger(arr |> Array.map BitConverter.GetBytes |> Array.concat).Mod(scalarOrder)

    createScalar r1, createScalar r2

let UpdateCommit (commit: uint256) (lpt: ECPoint) (rpt: ECPoint) : uint256 =
    let lpt = lpt.Normalize()
    let rpt = rpt.Normalize()

    let lparity = 
        (if EC.IsQuadVar (lpt.AffineYCoord) then 0uy else 2uy) 
        + (if EC.IsQuadVar (rpt.AffineYCoord) then 0uy else 1uy)

    let hasher = Sha256Digest()
    hasher.BlockUpdate(commit.ToBytes(), 0, 32)
    hasher.Update lparity
    hasher.BlockUpdate(lpt.AffineXCoord.GetEncoded(), 0, 32)
    hasher.BlockUpdate(rpt.AffineXCoord.GetEncoded(), 0, 32)
    
    let result = Array.zeroCreate<byte> 32
    hasher.DoFinal(result, 0) |> ignore
    result |> uint256

let SerializePoints (points: array<ECPoint>) (proof: array<byte>) (offset: int) =
    let bitVecLen = (points.Length + 7) / 8
    Array.fill proof offset bitVecLen 0uy

    points  |> Array.iteri (fun i point ->
        let x = point.Normalize().XCoord
        Array.blit (x.GetEncoded()) 0 proof (offset + bitVecLen + i * 32) 32
        if not(IsQuadVar point.YCoord) then
            proof.[offset + i / 8] <- proof.[offset + i / 8] ||| uint8(i % 8)
    )

type private LrGenerator(nonce: uint256, y: BigInteger, z: BigInteger, nbits: int, value: uint64) =
    let mutable count = 0
    let mutable z22n = BigInteger.Zero
    let mutable yn = BigInteger.Zero

    member self.Generate(x: BigInteger) : BigInteger * BigInteger =
        let commitIdx = count / nbits
        let bitIdx = count % nbits
        let bit = (value >>> bitIdx) &&& 1UL

        if bitIdx = 0 then
            z22n <- z.Square()
            for i=0 to commitIdx do
                z22n <- z22n.Multiply z

        let sl, sr = ScalarChaCha20 nonce (uint64(count + 2))
        let sl = sl.Multiply x
        let sr = sr.Multiply x

        let lOut = BigInteger.ValueOf(int64 bit).Subtract(z).Add(sl)
        let rOut = BigInteger.ValueOf(1L - (int64 bit)).Negate().Add(z).Add(sr).Multiply(yn).Add(z22n)

        count <- count + 1

        yn <- yn.Multiply y
        z22n <- z22n.Add z22n 

        lOut.Mod(scalarOrder), rOut.Mod(scalarOrder)

type private ABHGData =
    {
        X: BigInteger
        Cache: BigInteger
        LrGen: LrGenerator
    }

let IP_AB_SCALARS = 4

let PopCount n =
    let mutable ret = 0
    let mutable x = n
    for i=0 to 63 do
        ret <- ret + x &&& 1
        x <- x >>> 1
    ret

// https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/modules/bulletproofs/util.h#L11
let FloorLog (n: uint32) =
    if n = 0u then
        0u
    else
        System.Math.Log(float n, 2.0) |> floor |> uint32

let InnerProductRealProve 
    (g: ECPoint) 
    (geng: array<ECPoint>)
    (genh: array<ECPoint>)
    (aArr: array<BigInteger>)
    (bArr: array<BigInteger>)
    (yInv: BigInteger)
    (ux: BigInteger)
    (n: int)
    (commit: uint256) 
    : array<ECPoint> =
    let SECP256K1_BULLETPROOF_MAX_DEPTH = 31
    let x = Array.create SECP256K1_BULLETPROOF_MAX_DEPTH BigInteger.Zero
    let xInv = Array.create SECP256K1_BULLETPROOF_MAX_DEPTH BigInteger.Zero
    
    let outPts = ResizeArray<ECPoint>()
    let mutable commit = commit
    
    // Protocol 1: Iterate, halving vector size until it is 1
    let vSizes = 
        Seq.unfold 
            (fun halfwidth -> 
                if halfwidth > IP_AB_SCALARS / 4 then
                    Some(halfwidth / 2, halfwidth / 2)
                else
                    None)
            (n / 2)
    vSizes |> Seq.iteri (fun i halfwidth ->
        let mutable yInvN = BigInteger.One

        let multCallbackLR (odd: int) (gSc: BigInteger) (grouping: int) (idx: int) =
            let abIdx = (idx / grouping) ^^^ 1
            // Special-case the primary generator
            if idx = n then
                g, gSc
            else
                // steps 1/2
                let pt, sc =
                    if idx / grouping % 2 = odd then
                        let sc = bArr.[abIdx].Multiply yInvN
                        genh.[idx], sc
                    else
                        geng.[idx], aArr.[abIdx]
                // step 3
                let mutable sc = sc
                let groupings = 
                    Seq.initInfinite (fun i -> 1u <<< i)
                    |> Seq.takeWhile (fun each -> each < uint32 grouping)
                groupings |> Seq.iteri (fun i gr ->
                    if (((idx / int gr) % 2) ^^^ ((idx / grouping) % 2)) = odd then
                        sc <- sc.Multiply x.[i]
                    else
                        sc <- sc.Multiply xInv.[i]
                )
                pt, sc.Mod(scalarOrder)
        
        let multMultivar (inpGSc: BigInteger) (callback: int -> (ECPoint * BigInteger)) (nPoints: int) =
            let mutable r = generatorG.Multiply inpGSc // Is it the right G?
            for pointIdx=0 to nPoints-1 do
                let point, scalar = callback pointIdx
                r <- r.Add(point.Multiply scalar)
            r

        // L
        let gSc =
            ([| for j=0 to halfwidth-1 do yield aArr.[2*j].Multiply bArr.[2*j+1] |]
             |> Array.fold (fun (a : BigInteger)b -> a.Add b) BigInteger.Zero)
             .Multiply(ux).Mod(scalarOrder)
        
        outPts.Add(multMultivar gSc (multCallbackLR 0 gSc (1 <<< i)) (n + 1))

        // R 
        let gSc =
            ([| for j=0 to halfwidth-1 do yield aArr.[2*j+1].Multiply bArr.[2*j] |]
             |> Array.fold (fun (a : BigInteger)b -> a.Add b) BigInteger.Zero)
             .Multiply(ux).Mod(scalarOrder)

        outPts.Add(multMultivar gSc (multCallbackLR 1 gSc (1 <<< i)) (n + 1))

        // x, x^2, x^-1, x^-2
        commit <-
            UpdateCommit 
                commit
                outPts.[outPts.Count - 2]
                outPts.[outPts.Count - 1]

        x.[i] <- commit.ToBytes() |> BigInteger.FromByteArrayUnsigned
        xInv.[i] <- x.[i].ModInverse(scalarOrder)

        // update scalar array
        for j=0 to halfwidth-1 do
            aArr.[2*j] <- aArr.[2*j].Multiply x.[i]
            aArr.[j] <- aArr.[2*j].Add(aArr.[2*j+1].Multiply xInv.[i])

            bArr.[2*j] <- bArr.[2*j].Multiply xInv.[i]
            bArr.[j] <- bArr.[2*j].Add(bArr.[2*j+1].Multiply x.[i])
    )

    // I skipped last section, since it seems that this is just optimization and thus optional.
    // But I'm not 100% sure. yInv is unused.
    // https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/modules/bulletproofs/inner_product_impl.h#L719
    outPts.ToArray()

let InnerProductProofLength (n: int) =
    if n < IP_AB_SCALARS / 2 then
        32 * (1 + 2 * n)
    else
        let bitCount = PopCount n
        let log = FloorLog <| uint32(2 * n / IP_AB_SCALARS)
        32 * (1 + 2 * (bitCount - 1 + int log) + IP_AB_SCALARS) + int(2u * log + 7u) / 8

let InnerProductProve 
    (proof: array<byte>) 
    (proofOffset: int)
    (proofLen: ref<int>) 
    (generators: array<ECPoint>) 
    (yInv: BigInteger) 
    (n: int) 
    (cb: ref<BigInteger> -> Option<ECPoint> -> int -> unit)
    (commitInp: array<byte>) =
    proofLen.Value <- InnerProductProofLength n
    
    let dotProduct (a: array<ref<BigInteger>>) (b: array<ref<BigInteger>>) =
        (Array.map2 (fun (x : BigInteger ref) (y : BigInteger ref) -> x.Value.Multiply y.Value) a b
        |> Array.fold (fun (x : BigInteger) y -> x.Add y) BigInteger.Zero)
            .Mod(scalarOrder)

    // Special-case lengths 0 and 1 whose proofs are just explicit lists of scalars
    if n <= IP_AB_SCALARS / 2 then
        let a = Array.create (IP_AB_SCALARS / 2) (ref BigInteger.Zero)
        let b = Array.create (IP_AB_SCALARS / 2) (ref BigInteger.Zero)
        for i=0 to n-1 do
            cb a.[i] None (2 * i)
            cb b.[i] None (2 * i + 1)
        let dot = dotProduct a b
        Array.blit (dot.ToUInt256().ToBytes()) 0 proof proofOffset 32
        for i=0 to n-1 do
            Array.blit (a.[i].Value.ToUInt256().ToBytes()) 0 proof (proofOffset + 32 * (i + 1)) 32
            Array.blit (b.[i].Value.ToUInt256().ToBytes()) 0 proof (proofOffset + 32 * (i + n + 1)) 32
    else
        let aArr = Array.create n (ref BigInteger.Zero)
        let bArr = Array.create n (ref BigInteger.Zero)
        let geng = generators |> Array.take n
        let genh = generators |> Array.skip (generators.Length / 2) |> Array.take n
        for i=0 to n-1 do
            cb aArr.[i] None (2 * i)
            cb bArr.[i] None (2 * i + 1)

        // Record final dot product
        let dot = dotProduct aArr bArr
        Array.blit (dot.ToUInt256().ToBytes()) 0 proof proofOffset 32
            
        // Protocol 2: hash dot product to obtain G-randomizer
        let commit = 
            let hasher = Sha256Digest()
            hasher.BlockUpdate(commitInp, 0, commitInp.Length)
            hasher.BlockUpdate(proof, proofOffset, 32)
            let bytes = Array.zeroCreate<byte> 32
            hasher.DoFinal(bytes, 0) |> ignore
            bytes

        let proofOffset = proofOffset + 32
        
        let ux = BigInteger.FromByteArrayUnsigned commit

        let outPts = InnerProductRealProve generatorG geng genh (aArr |> Array.map (!)) (bArr |> Array.map (!)) yInv ux n (uint256 commit)

        // Final a/b values
        let halfNAB = min (IP_AB_SCALARS / 2) n
        for i=0 to halfNAB-1 do
            Array.blit (aArr.[i].Value.ToUInt256().ToBytes()) 0 proof (proofOffset + 32 * i) 32
            Array.blit (bArr.[i].Value.ToUInt256().ToBytes()) 0 proof (proofOffset + 32 * (i + halfNAB)) 32
        
        let proofOffset = proofOffset + 64 * halfNAB

        SerializePoints outPts proof proofOffset
        // commit?

let ConstructRangeProof 
    (amount: uint64) 
    (key: uint256) 
    (privateNonce: uint256) 
    (rewindNonce: uint256) 
    (proofMessage: array<byte>) 
    (extraData: array<byte>) : RangeProof =
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
        let vals = BigInteger.ValueOf(int64 amount)
        // Combine value with 20 bytes of optional message
        let vals_bytes = vals.ToUInt256().ToBytes()
        for i=0 to 20-1 do
            vals_bytes.[i+4] <- proofMessage.[i]
        let vals = BigInteger vals_bytes
        // Negate so it'll be positive in -mu
        let vals = vals.Negate()
        alpha.Add vals

    let nbits = 64

    let generators = 
        let random = SecureRandom()
        Array.init 
            256 
            (fun _ -> 
                curve.G.Multiply((curve.Curve.RandomFieldElement random).ToBigInteger()) )
    // Compute A and S
    let aL = Array.init nbits (fun i -> amount &&& uint64(1UL <<< i))
    //let aR = aL |> Array.map (fun n -> 1UL - n)
    let mutable aj = generatorG.Multiply alpha
    let mutable sj = generatorG.Multiply rho
    for j=0 to nbits - 1 do
        let aterm = generators.[j + generators.Length / 2].Negate()
        let sl, sr = ScalarChaCha20 rewindNonce (uint64(j + 2))
        let aterm =
            curve.Curve.CreatePoint(
                (if aL.[j] <> 0UL then generators.[j].XCoord else aterm.XCoord).ToBigInteger(),
                (if aL.[j] <> 0UL then generators.[j].YCoord else aterm.YCoord).ToBigInteger())
        aj <- aj.Add aterm
        sj <- sj.Add(generators.[j].Multiply sl).Add(generators.[j + generators.Length / 2].Multiply sr)

    // get challenges y and z
    let outPt0 = aj
    let outPt1 = sj
    let commit = UpdateCommit (uint256 commit) outPt0 outPt1
    let y = BigInteger(commit.ToBytes()).Mod(scalarOrder)
    // do it twice like in secp256k1-zkp sources
    let commit = UpdateCommit (uint256 commit) outPt0 outPt1
    let z = BigInteger(commit.ToBytes()).Mod(scalarOrder)

    // Compute coefficients t0, t1, t2 of the <l, r> polynomial
    // t0 = l(0) dot r(0)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let t0 = 
        (Array.fold
            (fun (acc : BigInteger) _ -> 
                let l, r = lrGen.Generate BigInteger.Zero
                l.Multiply(r).Add acc)
            BigInteger.Zero
            (Array.zeroCreate nbits)).Mod(scalarOrder)
    
    // A = t0 + t1 + t2 = l(1) dot r(1)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let A = 
        (Array.fold
            (fun (acc : BigInteger) _ -> 
                let l, r = lrGen.Generate BigInteger.One
                l.Multiply(r).Add acc)
            BigInteger.Zero
            (Array.zeroCreate nbits)).Mod(scalarOrder)
    
    // B = t0 - t1 + t2 = l(-1) dot r(-1)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let B = 
        (Array.fold
            (fun (acc : BigInteger) _ -> 
                let l, r = lrGen.Generate (BigInteger.One.Negate())
                l.Multiply(r).Add acc)
            BigInteger.Zero
            (Array.zeroCreate nbits)).Mod(scalarOrder)

    // t1 = (A - B)/2
    let t1 = A.Subtract(B).Divide(BigInteger.Two).Mod(scalarOrder)

    // t2 = -(-B + t0) + t1
    let t2 = B.Negate().Add(t0).Negate().Add(t1).Mod(scalarOrder)

    // Compute Ti = t_i*A + tau_i*G for i = 1,2
    // Normal bulletproof: T1=t1*A + tau1*G
    let outPt2 = generatorG.Multiply(tau1).Add(generatorH.Multiply t1)
    let outPt3 = generatorG.Multiply(tau2).Add(generatorH.Multiply t2)

    let commit = UpdateCommit commit outPt2 outPt3
    let x = BigInteger(commit.ToBytes()).Mod(scalarOrder)

    // compute tau_x and mu
    // Negate taux and mu so the verifier doesn't have to
    let tauX = 
        tau1
            .Multiply(x)
            .Add(tau2.Multiply(x.Square()))
            .Add(z.Square().Multiply(key.ToBytes() |> BigInteger))
            .Negate()
            .Mod(scalarOrder)

    let mu = rho.Multiply(x).Add(alpha).Negate().Mod(scalarOrder)

    // Encode rangeproof stuff
    let proof : array<byte> = Array.zeroCreate RangeProof.Size
    Array.blit (tauX.ToByteArrayUnsigned()) 0 proof 0 32
    Array.blit (mu.ToByteArrayUnsigned()) 0 proof 32 32
    SerializePoints [| outPt0; outPt1; outPt2; outPt3 |] proof 64

    // Mix this into the hash so the input to the inner product proof is fixed
    let commit =
        let hasher = Sha256Digest()
        hasher.BlockUpdate(commit.ToBytes(), 0, 32)
        hasher.BlockUpdate(proof, 0, 64)
        let hash = Array.zeroCreate 32
        hasher.DoFinal(hash, 0) |> ignore
        hash

    // Compute l and r, do inner product proof
    let abhgData = 
        ref { 
            X = x; 
            Cache = BigInteger.Zero; 
            LrGen = LrGenerator(rewindNonce, y, z, nbits, amount) 
        }
    let callback (sc: ref<BigInteger>) (pt: Option<ECPoint>) (idx: int) =
        let isG = idx % 2 = 0
        if isG then
            let cache, x = abhgData.Value.LrGen.Generate sc.Value
            abhgData.Value <- { abhgData.Value with Cache = cache; X = x }
        else
            sc.Value <- abhgData.Value.Cache

    let innerProductProofLength = 64 + 128 + 1
    let plen = ref(RangeProof.Size - innerProductProofLength)
    
    let y = y.ModInverse scalarOrder
    InnerProductProve proof innerProductProofLength plen generators y nbits callback commit

    plen.Value <- plen.Value + innerProductProofLength
    
    assert(plen.Value = RangeProof.Size)
    RangeProof proof
