module NLitecoin.MimbleWimble.Bulletproof

open System

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Math
open Org.BouncyCastle.Math.EC
open NBitcoin

open EC

type HmacSha256(key: array<byte>) =
    let outer = Sha256Digest()
    let inner = Sha256Digest()
    do
        let rKey = Array.zeroCreate<byte> 64
        Array.blit key 0 rKey 0 key.Length
        
        for n=0 to rKey.Length-1 do
            rKey.[n] <- rKey.[n] ^^^ 0x5cuy
        outer.BlockUpdate(rKey, 0, 64)

        for n=0 to rKey.Length-1 do
            rKey.[n] <- rKey.[n] ^^^ 0x5cuy ^^^ 0x36uy
        inner.BlockUpdate(rKey, 0, 64)

    member self.Write(data: array<byte>) =
        inner.BlockUpdate(data, 0, data.Length)

    member self.Finalize(out32: array<byte>) =
        assert(out32.Length = 32)
        let temp = Array.zeroCreate<byte> 32
        inner.DoFinal(temp, 0) |> ignore
        outer.BlockUpdate(temp, 0, 32)
        outer.DoFinal(out32, 0) |> ignore

type Rfc6979HmacSha256(key: array<byte>) =
    let k = Array.create 32 0uy
    let v = Array.create 32 1uy

    do        
        let hmac = HmacSha256 k
        hmac.Write v
        hmac.Write [| 0uy |]
        hmac.Write key
        hmac.Finalize k
        let hmac = HmacSha256 k
        hmac.Write v
        hmac.Finalize v

        let hmac = HmacSha256 k
        hmac.Write v
        hmac.Write [| 1uy |]
        hmac.Write key
        hmac.Finalize k
        let hmac = HmacSha256 k
        hmac.Write v
        hmac.Finalize v

    let mutable retry = false

    member self.Generate(outLen: int) : array<byte> =
        if retry then
            let hmac = HmacSha256 k
            hmac.Write v
            hmac.Write [| 0uy |]
            hmac.Finalize k
            let hmac = HmacSha256 k
            hmac.Write v
            hmac.Finalize v
            
        let mutable outLen = outLen
        let out = ResizeArray<byte>()
        while outLen > 0 do
            let now = min 32 outLen
            let hmac = HmacSha256 k
            hmac.Write v
            hmac.Finalize v
            out.AddRange(v |> Array.take now)
            outLen <- outLen - now

        retry <- true

        out.ToArray()

let ShallueVanDeWoestijne(t: ECFieldElement) : ECPoint =
    let c = 
        BigInteger("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852", 16) 
        |> curve.Curve.FromBigInteger 
    let d = 
        BigInteger("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40", 16) 
        |> curve.Curve.FromBigInteger
    let b = curve.Curve.FromBigInteger(BigInteger.ValueOf 7L)

    let w = c.Multiply(t).Divide(b.AddOne().Add(t.Square()))
    let x1 = d.Subtract(t.Multiply w)
    let x2 = x1.AddOne().Negate()
    let x3 = w.Square().Invert().AddOne()

    let alphaIn = x1.Square().Multiply(x1).Add(b)
    let betaIn = x2.Square().Multiply(x2).Add(b)
    let gammaIn = x3.Square().Multiply(x3).Add(b)

    let alphaQuad = IsQuadVar alphaIn
    let y1 = alphaIn.Sqrt()
    let betaquad = IsQuadVar betaIn
    let y2 = betaIn.Sqrt()
    let y3 = gammaIn.Sqrt()

    let x1 = if (not alphaQuad) && betaquad then x2 else x1
    let y1 = if (not alphaQuad) && betaquad then y2 else y1
    let x1 = if (not alphaQuad) && not betaquad then x3 else x1
    let y1 = if (not alphaQuad) && not betaquad then y3 else y1

    let res = curve.Curve.CreatePoint(x1.ToBigInteger(), y1.ToBigInteger())
    if t.ToBigInteger().Mod(BigInteger.Two) = BigInteger.One then
        curve.Curve.CreatePoint(
            res.XCoord.ToBigInteger(), 
            res.YCoord.Negate().ToBigInteger()
        )
    else
        res

let GeneratorGenerate (key: array<byte>) : ECPoint =
    let prefix1 = "1st generation: " |> Text.ASCIIEncoding.ASCII.GetBytes
    let prefix2 = "2nd generation: " |> Text.ASCIIEncoding.ASCII.GetBytes
    let sha256 = Sha256Digest()
    sha256.BlockUpdate(prefix1, 0, 16)
    sha256.BlockUpdate(key, 0, 32)
    let b32 = Array.zeroCreate<byte> 32
    sha256.DoFinal(b32, 0) |> ignore
    let t = BigInteger.FromByteArrayUnsigned b32 |> curve.Curve.FromBigInteger
    let accum = ShallueVanDeWoestijne t

    let sha256 = Sha256Digest()
    sha256.BlockUpdate(prefix2, 0, 16)
    sha256.BlockUpdate(key, 0, 32)
    sha256.DoFinal(b32, 0) |> ignore
    let t = BigInteger.FromByteArrayUnsigned b32 |> curve.Curve.FromBigInteger
    let accum = accum.Add(ShallueVanDeWoestijne t)

    accum.Normalize()

let GetGenerators (n: int) : array<ECPoint> =
    let seed = Array.append (generatorG.XCoord.GetEncoded()) (generatorG.YCoord.GetEncoded())
    let rng = Rfc6979HmacSha256 seed
    Array.init 
        n
        (fun _ -> GeneratorGenerate (rng.Generate 32))

let ScalarDotProduct (vec1: array<BigInteger>, vec2: array<BigInteger>) : BigInteger =
    (Array.map2 (fun (x : BigInteger) y -> x.Multiply y) vec1 vec2
    |> Array.fold (fun (x : BigInteger) y -> x.Add y) BigInteger.Zero)
        .Mod(scalarOrder)

// port of https://github.com/litecoin-project/litecoin/blob/5ac781487cc9589131437b23c69829f04002b97e/src/secp256k1-zkp/src/scalar.h#L114
let ScalarChaCha20 (seed: uint256) (index: uint64) : BigInteger * BigInteger =
    let seed32 = seed.ToBytes() |> Array.chunkBySize 4 |> Array.map BitConverter.ToUInt32
    let mutable x = Array.zeroCreate<uint32> 16
    let mutable r1 = BigInteger.Zero
    let mutable r2 = BigInteger.Zero
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

    let inline ROTL32(x: uint32, n) = ((x) <<< (n)) ||| ((x) >>> (32-(n)))

    let QUARTERROUND (a,b,c,d) = 
        x.[a] <- x.[a] + x.[b]
        x.[d] <- ROTL32(x.[d] ^^^ x.[a], 16)
        x.[c] <- x.[c] + x.[d]
        x.[b] <- ROTL32(x.[b] ^^^ x.[c], 12)
        x.[a] <- x.[a] + x.[b]
        x.[d] <- ROTL32(x.[d] ^^^ x.[a], 8)
        x.[c] <- x.[c] + x.[d]
        x.[b] <- ROTL32(x.[b] ^^^ x.[c], 7)

    let createScalar (arr: array<uint64>) =
        arr 
            |> Array.map BitConverter.GetBytes 
            |> Array.concat
            |> Array.rev
            |> BigInteger.FromByteArrayUnsigned

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

        for _=1 to 10 do
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
        r1 <-
            [| 
                BE32(uint64 x.[6]) <<< 32 ||| BE32(uint64 x.[7])
                BE32(uint64 x.[4]) <<< 32 ||| BE32(uint64 x.[5])
                BE32(uint64 x.[2]) <<< 32 ||| BE32(uint64 x.[3])
                BE32(uint64 x.[0]) <<< 32 ||| BE32(uint64 x.[1])
            |]
            |> createScalar
        r2 <-
            [|
                BE32(uint64 x.[14]) <<< 32 ||| BE32(uint64 x.[15])
                BE32(uint64 x.[12]) <<< 32 ||| BE32(uint64 x.[13])
                BE32(uint64 x.[10]) <<< 32 ||| BE32(uint64 x.[11])
                BE32(uint64 x.[8])  <<< 32 ||| BE32(uint64 x.[9])
            |]
            |> createScalar

        over1 <- r1 >= scalarOrder
        over2 <- r2 >= scalarOrder

        overCount <- overCount + 1u

    r1, r2

let UpdateCommit (commit: uint256) (lpt: ECPoint) (rpt: ECPoint) : uint256 =
    let lpt = lpt.Normalize()
    let rpt = rpt.Normalize()

    let lrparity = 
        (if IsQuadVar lpt.AffineYCoord then 0uy else 2uy) 
        + (if IsQuadVar rpt.AffineYCoord then 0uy else 1uy)

    let hasher = Sha256Digest()
    hasher.BlockUpdate(commit.ToBytes(), 0, 32)
    hasher.Update lrparity
    hasher.BlockUpdate(lpt.AffineXCoord.GetEncoded(), 0, 32)
    hasher.BlockUpdate(rpt.AffineXCoord.GetEncoded(), 0, 32)
    
    let result = Array.zeroCreate<byte> 32
    hasher.DoFinal(result, 0) |> ignore
    result |> uint256

let SerializePoints (points: array<ECPoint>) (proof: Span<byte>) =
    let bitVecLen = (points.Length + 7) / 8
    proof.Slice(0, bitVecLen).Fill 0uy

    for i, point in points |> Seq.indexed do
        let x = point.Normalize().XCoord
        x.GetEncoded().CopyTo(proof.Slice(bitVecLen + i * 32))
        if not(IsQuadVar point.YCoord) then
            proof.[i / 8] <- proof.[i / 8] ||| uint8(1 <<< i % 8)

type private LrGenerator(nonce: uint256, y: BigInteger, z: BigInteger, nbits: int, value: uint64) =
    let mutable count = 0
    let mutable z22n = BigInteger.Zero
    let mutable yn = BigInteger.One

    member self.Generate(x: BigInteger) : BigInteger * BigInteger =
        // since we have only 1 commit, commitIdx = 0
        assert(count / nbits = 0)
        let bitIdx = count % nbits
        let bit = int64((value >>> bitIdx) &&& 1UL)

        if bitIdx = 0 then
            z22n <- z.Square()

        let sl, sr = ScalarChaCha20 nonce (uint64(count + 2))
        let al = BigInteger.ValueOf bit 
        let ar = BigInteger.ValueOf(1L - bit).Negate()

        let lOut = al.Subtract(z).Add(sl.Multiply x)
        let rOut = ar.Add(z).Add(sr.Multiply x).Multiply(yn).Add(z22n)

        count <- count + 1

        yn <- yn.Multiply y
        z22n <- z22n.Add z22n 

        lOut.Mod(scalarOrder), rOut.Mod(scalarOrder)

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

let rec InnerProductRealProve 
    (g: ECPoint) 
    (geng: array<ECPoint>)
    (genh: array<ECPoint>)
    (aArr: array<BigInteger>)
    (bArr: array<BigInteger>)
    (yInv: BigInteger)
    (ux: BigInteger)
    (n: int)
    (commit: uint256) 
    (recurse: bool)
    : array<ECPoint> =
    let SECP256K1_BULLETPROOF_MAX_DEPTH = 31
    let x = Array.create SECP256K1_BULLETPROOF_MAX_DEPTH BigInteger.Zero
    let xInv = Array.create SECP256K1_BULLETPROOF_MAX_DEPTH BigInteger.Zero
    
    let outPts = ResizeArray<ECPoint>()
    let mutable commit = commit

    let mutable pfDataGeng = geng
    let mutable pfDataGenh = genh
    let mutable yInvN = BigInteger.One
    let mutable keepIterating = true
    
    // Protocol 1: Iterate, halving vector size until it is 1
    let vSizes = 
        Seq.unfold 
            (fun halfwidth -> 
                if halfwidth > IP_AB_SCALARS / 4 then
                    Some(halfwidth / 2, halfwidth / 2)
                else
                    None)
            (n / 2)
    vSizes 
    |> Seq.takeWhile (fun _ -> keepIterating) 
    |> Seq.iteri (fun i halfwidth ->
        let grouping = (1 <<< i)

        let multCallbackLR (odd: int) (gSc: BigInteger) (idx: int) =
            let abIdx = (idx / grouping) ^^^ 1
            // Special-case the primary generator
            if idx = n then
                g, gSc
            else
                // steps 1/2
                let pt, sc =
                    if idx / grouping % 2 = odd then
                        let sc = bArr.[abIdx].Multiply yInvN
                        pfDataGenh.[idx], sc
                    else
                        pfDataGeng.[idx], aArr.[abIdx]
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
        
        let multMultivar (callback: int -> (ECPoint * BigInteger)) (nPoints: int) =
            let mutable r = generatorG.Multiply(BigInteger.Zero)
            for pointIdx=0 to nPoints-1 do
                let point, scalar = callback pointIdx
                r <- r.Add(point.Multiply scalar)
            r

        // L
        let gSc =
            ([| for j=0 to halfwidth-1 do yield aArr.[2*j].Multiply bArr.[2*j+1] |]
             |> Array.fold (fun (a : BigInteger)b -> a.Add b) BigInteger.Zero)
             .Multiply(ux).Mod(scalarOrder)
        
        outPts.Add(multMultivar (multCallbackLR 0 gSc) (n + 1))

        // R 
        let gSc =
            ([| for j=0 to halfwidth-1 do yield aArr.[2*j+1].Multiply bArr.[2*j] |]
             |> Array.fold (fun (a : BigInteger)b -> a.Add b) BigInteger.Zero)
             .Multiply(ux).Mod(scalarOrder)

        outPts.Add(multMultivar (multCallbackLR 1 gSc) (n + 1))

        // x, x^2, x^-1, x^-2
        commit <-
            UpdateCommit 
                commit
                outPts.[outPts.Count - 2]
                outPts.[outPts.Count - 1]

        x.[i] <- (commit.ToBytes() |> BigInteger.FromByteArrayUnsigned).Mod(scalarOrder)
        xInv.[i] <- x.[i].ModInverse(scalarOrder)

        // update scalar array
        for j=0 to halfwidth-1 do
            aArr.[2*j] <- aArr.[2*j].Multiply(x.[i]).Mod(scalarOrder)
            aArr.[j] <- aArr.[2*j].Add(aArr.[2*j+1].Multiply xInv.[i]).Mod(scalarOrder)

            bArr.[2*j] <- bArr.[2*j].Multiply(xInv.[i]).Mod(scalarOrder)
            bArr.[j] <- bArr.[2*j].Add(bArr.[2*j+1].Multiply x.[i]).Mod(scalarOrder)
        
        // Combine G generators and recurse, if that would be more optimal
        // Is it needed? Or it's just an optimization?
        if recurse && ((n > 2048 && i = 3) || (n > 128 && i = 2) || (n > 32 && i = 1)) then
            let multCallbackG (idx: int) =
                let pt = pfDataGeng.[idx]
                let mutable sc = BigInteger.One
                let indices = 
                    Seq.initInfinite id
                    |> Seq.takeWhile (fun i -> 1 <<< i < grouping)
                for i in indices do
                    if idx &&& (1 <<< i) <> 0 then
                        sc <- sc.Multiply x.[i]
                    else
                        sc <- sc.Multiply xInv.[i]
                pt, sc.Mod scalarOrder
            
            let multCallbackH (idx: int) =
                let pt = pfDataGenh.[idx]
                let mutable sc = BigInteger.One
                let indices = 
                    Seq.initInfinite id
                    |> Seq.takeWhile (fun i -> 1 <<< i < grouping)
                for i in indices do
                    if idx &&& (1 <<< i) <> 0 then
                        sc <- sc.Multiply xInv.[i]
                    else
                        sc <- sc.Multiply x.[i]
                sc <- sc.Multiply yInvN
                yInvN <- yInvN.Multiply(yInv).Mod(scalarOrder)
                pt, sc.Mod scalarOrder

            for j=0 to halfwidth-1 do
                let rG = multMultivar multCallbackG (2 <<< i)
                pfDataGeng <- pfDataGeng |> Array.skip (2 <<< i)
                geng.[j] <- rG
                yInvN <- BigInteger.One
                let rH = multMultivar multCallbackH (2 <<< i)
                pfDataGenh <- pfDataGenh |> Array.skip (2 <<< i)
                genh.[j] <- rH
            
            let mutable yInv2 = yInv.Square()
            for _=0 to i-1 do
                yInv2 <- yInv2.Square()
            yInv2 <- yInv2.Mod(scalarOrder)

            InnerProductRealProve g geng genh aArr bArr yInv2 ux halfwidth commit recurse
            |> outPts.AddRange
            // break
            keepIterating <- false
    )

    outPts.ToArray()

let InnerProductProofLength (n: int) =
    if n < IP_AB_SCALARS / 2 then
        32 * (1 + 2 * n)
    else
        let bitCount = PopCount n
        let log = FloorLog <| uint32(2 * n / IP_AB_SCALARS)
        32 * (1 + 2 * (bitCount - 1 + int log) + IP_AB_SCALARS) + int(2u * log + 7u) / 8

let InnerProductProve 
    (proof: Span<byte>) 
    (generators: array<ECPoint>) 
    (yInv: BigInteger) 
    (n: int) 
    (createArrays: int -> (array<BigInteger> * array<BigInteger>))
    (commitInp: array<byte>)
    (recurse: bool)  =
    let proofLen = InnerProductProofLength n
        
    if n <= IP_AB_SCALARS / 2 then
        // Special-case lengths 0 and 1 whose proofs are just explicit lists of scalars
        let a, b = createArrays(IP_AB_SCALARS / 2)
        let dot = ScalarDotProduct(a, b)
        dot.ToUInt256().ToBytes().CopyTo proof
        for i=0 to n-1 do
            a.[i].ToUInt256().ToBytes().CopyTo(proof.Slice(32 * (i + 1)))
            b.[i].ToUInt256().ToBytes().CopyTo(proof.Slice(32 * (i + n + 1)))
    else
        let aArr, bArr = createArrays n
        let geng = generators |> Array.take n
        let genh = generators |> Array.skip (generators.Length / 2) |> Array.take n

        // Record final dot product
        let dot = ScalarDotProduct(aArr, bArr)
        dot.ToUInt256().ToBytes().CopyTo proof
            
        // Protocol 2: hash dot product to obtain G-randomizer
        let commit = 
            let hasher = Sha256Digest()
            hasher.BlockUpdate(commitInp, 0, commitInp.Length)
            hasher.BlockUpdate(proof.ToArray(), 0, 32)
            let bytes = Array.zeroCreate<byte> 32
            hasher.DoFinal(bytes, 0) |> ignore
            bytes

        let proof = proof.Slice 32
        
        let ux = BigInteger.FromByteArrayUnsigned commit

        let outPts = InnerProductRealProve generatorG geng genh aArr bArr yInv ux n (uint256 commit) recurse

        // Final a/b values
        let halfNAB = min (IP_AB_SCALARS / 2) n
        for i=0 to halfNAB-1 do
            aArr.[i].ToUInt256().ToBytes().CopyTo(proof.Slice(32 * i))
            bArr.[i].ToUInt256().ToBytes().CopyTo(proof.Slice(32 * (i + halfNAB)))
        
        let proof = proof.Slice(64 * halfNAB)

        SerializePoints outPts proof

    proofLen

let ConstructRangeProof 
    (amount: uint64) 
    (key: uint256) 
    (privateNonce: uint256) 
    (rewindNonce: uint256) 
    (proofMessage: array<byte>) 
    (extraData: Option<array<byte>>) : RangeProof =
    let commitp = 
        generatorH.Multiply(BigInteger.ValueOf(int64 amount))
            .Add(generatorG.Multiply(key.ToBytes() |> BigInteger.FromByteArrayUnsigned))

    let commit = UpdateCommit uint256.Zero commitp generatorH

    let commit = 
        match extraData with
        | Some bytes ->
            let hasher = Sha256Digest()
            hasher.BlockUpdate(commit.ToBytes(), 0, 32)
            hasher.BlockUpdate(bytes, 0, bytes.Length)
            let result = Array.zeroCreate<byte> 32
            hasher.DoFinal(result, 0) |> ignore
            uint256 result
        | None ->
            commit

    let alpha, rho = ScalarChaCha20 rewindNonce 0UL
    let tau1, tau2 = ScalarChaCha20 privateNonce 1UL

    // Encrypt value into alpha, so it will be recoverable from -mu by someone who knows rewindNonce
    let alpha = 
        let vals = BigInteger.ValueOf(int64 amount)
        // Combine value with 20 bytes of optional message
        let vals_bytes = vals.ToUInt256().ToBytes()
        for i=0 to 20-1 do
            vals_bytes.[i+4] <- proofMessage.[i]
        let vals = BigInteger.FromByteArrayUnsigned vals_bytes
        // Negate so it'll be positive in -mu
        let vals = vals.Negate()
        alpha.Add(vals).Mod(scalarOrder)

    let nbits = 64

    let generators = GetGenerators 256

    // Compute A and S
    let aL = Array.init nbits (fun i -> amount &&& uint64(1UL <<< i))
    let mutable a = generatorG.Multiply alpha
    let mutable s = generatorG.Multiply rho
    for j=0 to nbits - 1 do
        let sl, sr = ScalarChaCha20 rewindNonce (uint64(j + 2))
        let aterm = 
            if aL.[j] <> 0UL then 
                generators.[j] 
            else 
                generators.[j + generators.Length / 2].Negate()
        a <- a.Add aterm
        s <- s.Add(generators.[j].Multiply sl).Add(generators.[j + generators.Length / 2].Multiply sr)

    // get challenges y and z
    let outPt0 = a
    let outPt1 = s
    let commit = UpdateCommit commit outPt0 outPt1
    let y = BigInteger.FromByteArrayUnsigned(commit.ToBytes()).Mod(scalarOrder)
    let commit = UpdateCommit commit outPt0 outPt1
    let z = BigInteger.FromByteArrayUnsigned(commit.ToBytes()).Mod(scalarOrder)

    // Compute coefficients t0, t1, t2 of the <l, r> polynomial
    // t0 = l(0) dot r(0)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let t0 = 
        Array.init nbits (fun _ -> lrGen.Generate BigInteger.Zero)
        |> Array.unzip
        |> ScalarDotProduct
    
    // see Bulletproofs: Efficient Range Proofs for Confidential Transactions paper, p. 17
    let inline t0assertion() =
        let t0alt =
            let oneNyN = ScalarDotProduct(Array.create nbits BigInteger.One, Array.init nbits (fun n -> y.Pow n))
            let oneN2N = ScalarDotProduct(Array.create nbits BigInteger.One, Array.init nbits (fun n -> BigInteger.Two.Pow n))
            z.Multiply(oneNyN)
                .Add(z.Square().Multiply(BigInteger.ValueOf(int64 amount)))
                .Add(z.Square().Negate().Multiply(oneNyN).Subtract(z.Square().Multiply(z).Multiply(oneN2N)))
                .Mod(scalarOrder)
        t0alt = t0
    assert(t0assertion())

    // A = t0 + t1 + t2 = l(1) dot r(1)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let A = 
        Array.init nbits (fun _ -> lrGen.Generate BigInteger.One)
        |> Array.unzip
        |> ScalarDotProduct
    
    // B = t0 - t1 + t2 = l(-1) dot r(-1)
    let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount)
    let B = 
        Array.init nbits (fun _ -> lrGen.Generate (BigInteger.One.Negate().Mod(scalarOrder)))
        |> Array.unzip
        |> ScalarDotProduct

    // t1 = (A - B)/2
    let t1 = A.Subtract(B).Multiply(BigInteger.Two.ModInverse scalarOrder).Mod(scalarOrder)

    // t2 = -(-B + t0) + t1
    let t2 = B.Negate().Add(t0).Negate().Add(t1).Mod(scalarOrder)

    // Compute Ti = t_i*A + tau_i*G for i = 1,2
    // Normal bulletproof: T1=t1*A + tau1*G
    let outPt2 = generatorG.Multiply(tau1).Add(generatorH.Multiply t1)
    let outPt3 = generatorG.Multiply(tau2).Add(generatorH.Multiply t2)

    let commit = UpdateCommit commit outPt2 outPt3
    let x = BigInteger.FromByteArrayUnsigned(commit.ToBytes()).Mod(scalarOrder)

    // compute tau_x and mu
    // Negate taux and mu so the verifier doesn't have to
    let tauX = 
        tau1
            .Multiply(x)
            .Add(tau2.Multiply(x.Square()))
            .Add(z.Square().Multiply(key.ToBytes() |> BigInteger.FromByteArrayUnsigned))
            .Negate()
            .Mod(scalarOrder)

    let mu = rho.Multiply(x).Add(alpha).Negate().Mod(scalarOrder)

    // Encode rangeproof stuff
    let proof : array<byte> = Array.zeroCreate RangeProof.Size
    Array.blit (tauX.ToUInt256().ToBytes()) 0 proof 0 32
    Array.blit (mu.ToUInt256().ToBytes()) 0 proof 32 32
    SerializePoints [| outPt0; outPt1; outPt2; outPt3 |] (proof.AsSpan().Slice 64)

    // Mix this into the hash so the input to the inner product proof is fixed
    let commit =
        let hasher = Sha256Digest()
        hasher.BlockUpdate(commit.ToBytes(), 0, 32)
        hasher.BlockUpdate(proof, 0, 64)
        let hash = Array.zeroCreate 32
        hasher.DoFinal(hash, 0) |> ignore
        hash

    // Compute l and r, do inner product proof
    let results = 
        [ true; false ] 
        |> List.map (fun recurse -> 
            let proofCopy = Array.copy proof
            let lrGen = LrGenerator(rewindNonce, y, z, nbits, amount) 
            let createArraysCallback (n: int) =
                Array.init n (fun _ -> lrGen.Generate x)
                |> Array.unzip

            let innerProductProofOffset = 64 + 128 + 1
    
            let y = y.ModInverse scalarOrder
            let innerProductProofLength = 
                InnerProductProve (proofCopy.AsSpan().Slice innerProductProofOffset) generators y nbits createArraysCallback commit recurse
            proofCopy, innerProductProofLength
        )

    let proof,innerProductProofLength = results.[1]
    let diff = Array.map2 (fun x y -> x ^^^ y) (fst results.[0]) (fst results.[1])
    let innerProductProofOffset = 64 + 128 + 1
    assert(innerProductProofLength + innerProductProofOffset = RangeProof.Size)
    assert(proof.Length = RangeProof.Size)
    RangeProof proof
