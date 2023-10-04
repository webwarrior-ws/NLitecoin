module NLitecoin.MimbleWimble.Wallet

open System

open NBitcoin
open Org.BouncyCastle.Math

open EC

let KeyPurposeMweb = 100

type Coin = NLitecoin.MimbleWimble.Coin

type KeyChain(seed: array<byte>) as self =
    let masterKey = ExtKey.CreateFromSeed seed
    // derive m/0'
    let accountKey = masterKey.Derive(0, true)
    // derive m/0'/100' (MWEB)
    let chainChildKey = accountKey.Derive(KeyPurposeMweb, true)

    let scanKey = chainChildKey.Derive(0, true)
    let spendKey = chainChildKey.Derive(1, true)

    // have to use dictionary as Secp256k1.ECPrivKey doesn't implement comparison
    let spendPubKeysMap = Collections.Generic.Dictionary<Secp256k1.ECPrivKey, uint32>()
    do 
        for i in 0u..100u do spendPubKeysMap.[self.GetSpendKey i] <- i

    member self.GetIndexForSpendKey(key: Secp256k1.ECPrivKey) : Option<uint32> =
       match spendPubKeysMap.TryGetValue key with
       | (true, value) -> Some value
       | _ -> None

    member self.GetStealthAddress(index: uint32) : StealthAddress =
        let spendPubKey = self.GetSpendKey(index).CreatePubKey()
        {
            SpendPubKey = spendPubKey.ToBytes(true) |> BigInt |> PublicKey
            ScanPubKey = spendPubKey.TweakMul(scanKey.PrivateKey.ToBytes()).ToBytes(true) |> BigInt |> PublicKey
        }
    
    member self.GetSpendKey(index: uint32) : Secp256k1.ECPrivKey =
        let mi =
            let hasher = new Hasher(HashTags.ADDRESS)
            hasher.Write(BitConverter.GetBytes index)
            hasher.Write(scanKey.PrivateKey.ToBytes())
            hasher.Hash()
        
        Secp256k1.ECPrivKey.Create(spendKey.PrivateKey.ToBytes()).TweakAdd(mi.ToBytes())

    member self.RewindOutput(output: Output) : Option<Coin> =
        match output.Message.StandardFields with
        | None -> None
        | Some outputFields ->
            let sharedSecret = 
                Secp256k1.ECPubKey.Create(outputFields.KeyExchangePubkey.ToBytes())
                    .TweakMul(scanKey.PrivateKey.ToBytes())
                    .ToBytes(true) 
                    |> BigInt 
                    |> PublicKey
            let viewTag = 
                let hasher = Hasher(HashTags.TAG)
                hasher.Append sharedSecret
                hasher.Hash().ToBytes().[0]
            if viewTag <> outputFields.ViewTag then
                None
            else
                let t = 
                    let hasher = Hasher(HashTags.DERIVE)
                    hasher.Append sharedSecret
                    hasher.Hash()

                let Bi = 
                    let tHashed =
                        let hasher = Hasher(HashTags.OUT_KEY)
                        hasher.Append t
                        hasher.Hash().ToBytes() |> BigInteger.FromByteArrayUnsigned
                    curve.Curve.DecodePoint(output.ReceiverPublicKey.ToBytes())
                        .Multiply(tHashed.ModInverse EC.scalarOrder)
                
                match self.GetIndexForSpendKey(Secp256k1.ECPrivKey.Create(Bi.GetEncoded(true))) with
                | None -> None
                | Some i ->
                    let mask = OutputMask.FromShared(t.ToUInt256())
                    let value = mask.MaskValue outputFields.MaskedValue |> int64
                    let n = mask.MaskNonce outputFields.MaskedNonce

                    if Pedersen.Commit value (Pedersen.BlindSwitch mask.PreBlind value) <> output.Commitment then
                        None
                    else
                        
                        failwith "not yet implemented"

type Wallet(keyChain: KeyChain) =
    let mutable coins: Map<Hash, Coin> = Map.empty
    
    member self.AddCoin(coin: Coin) =
        coins <- coins |> Map.add coin.OutputId coin

    member self.GetCoin(outputId: Hash) : Option<Coin> = 
        coins |> Map.tryFind outputId

    member self.RewindOutput(output: Output) : Option<Coin> =
        match self.GetCoin(output.GetOutputID()) with
        | Some coin when coin.IsMine -> 
            // If the coin has the spend key, it's fully rewound. If not, try rewinding further.
            if coin.HasSpendKey then
                Some coin
            else
                keyChain.RewindOutput output
        | _ -> 
            match keyChain.RewindOutput output with
            | Some coin ->
                coins <- coins |> Map.add (output.GetOutputID()) coin
                Some coin
            | None -> None
