module NLitecoin.MimbleWimble.Wallet

open System

open NBitcoin
open Org.BouncyCastle.Math

open EC

let KeyPurposeMweb = 100

type Coin = NLitecoin.MimbleWimble.Coin
type MutableDictionary<'K,'V> = Collections.Generic.Dictionary<'K,'V>

type KeyChain(seed: array<byte>, maxUsedIndex: uint32) as self =
    let masterKey = ExtKey.CreateFromSeed seed
    // derive m/0'
    let accountKey = masterKey.Derive(0, true)
    // derive m/0'/100' (MWEB)
    let chainChildKey = accountKey.Derive(KeyPurposeMweb, true)

    let scanKey = chainChildKey.Derive(0, true)
    let spendKey = chainChildKey.Derive(1, true)

    // have to use dictionary as Secp256k1.ECPrivKey doesn't implement comparison
    let spendPubKeysMap = MutableDictionary<Secp256k1.ECPrivKey, uint32>()
    do 
        for i in 0u..maxUsedIndex do spendPubKeysMap.[self.GetSpendKey i] <- i

    new(seed: array<byte>) = KeyChain(seed, 100u)

    member self.MaxUsedIndex : uint32 = spendPubKeysMap.Values |> Seq.max

    member self.ScanKey = scanKey
    member self.SpendKey = spendKey

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
            let hasher = Hasher HashTags.ADDRESS
            hasher.Write(BitConverter.GetBytes index)
            hasher.Write(scanKey.PrivateKey.ToBytes())
            hasher.Hash()
        let spendKey =
            Secp256k1.ECPrivKey.Create(spendKey.PrivateKey.ToBytes()).TweakAdd(mi.ToBytes())
        
        if not(spendPubKeysMap.Values |> Seq.contains index) then
            spendPubKeysMap.[spendKey] <- index
        
        spendKey

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
                let hasher = Hasher HashTags.TAG
                hasher.Append sharedSecret
                hasher.Hash().ToBytes().[0]
            if viewTag <> outputFields.ViewTag then
                None
            else
                /// t
                let ecdheSharedSecret = 
                    let hasher = Hasher HashTags.DERIVE
                    hasher.Append sharedSecret
                    hasher.Hash()

                let spendPubKey = 
                    let tHashed =
                        let hasher = Hasher HashTags.OUT_KEY
                        hasher.Append ecdheSharedSecret
                        hasher.Hash().ToBytes() |> BigInteger.FromByteArrayUnsigned
                    curve.Curve.DecodePoint(output.ReceiverPublicKey.ToBytes())
                        .Multiply(tHashed.ModInverse EC.scalarOrder)
                
                match self.GetIndexForSpendKey(Secp256k1.ECPrivKey.Create(spendPubKey.GetEncoded(true))) with
                | None -> None
                | Some index ->
                    let mask = OutputMask.FromShared(ecdheSharedSecret.ToUInt256())
                    let value = mask.MaskValue outputFields.MaskedValue |> int64
                    /// n
                    let maskNonce = mask.MaskNonce outputFields.MaskedNonce

                    if Pedersen.Commit value (Pedersen.BlindSwitch mask.PreBlind value) <> output.Commitment then
                        None
                    else
                        let address = 
                            { 
                                SpendPubKey = spendPubKey.GetEncoded(true) |> BigInt |> PublicKey
                                ScanPubKey = 
                                    spendPubKey.Multiply(scanKey.PrivateKey.ToBytes() |> BigInteger.FromByteArrayUnsigned)
                                        .GetEncoded(true) 
                                        |> BigInt 
                                        |> PublicKey 
                            }
                        // sending key 's' and check that s*B ?= Ke
                        let sendKey = 
                            let hasher = Hasher HashTags.SEND_KEY
                            hasher.Append address.ScanPubKey
                            hasher.Append address.SpendPubKey
                            hasher.Write(BitConverter.GetBytes value)
                            hasher.Append maskNonce
                            hasher.Hash()
                        if outputFields.KeyExchangePubkey.ToBytes() <> 
                            spendPubKey.Multiply(sendKey.ToBytes() |> BigInteger.FromByteArrayUnsigned).GetEncoded(true) then
                            None
                        else
                            {
                                AddressIndex = index
                                Blind = Some mask.PreBlind
                                Amount = value
                                OutputId = output.GetOutputID()
                                Address = Some address
                                SharedSecret = Some(ecdheSharedSecret.ToUInt256())
                                SpendKey = self.CalculateOutputKey (ecdheSharedSecret.ToUInt256()) index
                                SenderKey = None
                            }
                            |> Some

    member private self.CalculateOutputKey (sharedSecret: uint256) (addressIndex: uint32) : Option<uint256> =
        if addressIndex = Coin.UnknownIndex || addressIndex = Coin.CustomKey then
            None
        else
            let sharedSecretHashed =
                let hasher = Hasher HashTags.OUT_KEY
                hasher.Append(sharedSecret.ToBytes() |> BigInt)
                hasher.Hash()
            self.GetSpendKey(addressIndex)
                .TweakMul(sharedSecretHashed.ToBytes())
                .ToBytes()
                |> uint256
                |> Some

type Wallet(keyChain: KeyChain, coins: Map<Hash, Coin>) =
    new(keyChain: KeyChain) = Wallet(keyChain, Map.empty)

    member self.AddCoin(coin: Coin) : Wallet =
        Wallet(keyChain, coins |> Map.add coin.OutputId coin)

    member self.GetCoin(outputId: Hash) : Option<Coin> = 
        coins |> Map.tryFind outputId

    member self.RewindOutput(output: Output) : Wallet * Option<Coin> =
        match self.GetCoin(output.GetOutputID()) with
        | Some coin when coin.IsMine -> 
            // If the coin has the spend key, it's fully rewound. If not, try rewinding further.
            if coin.HasSpendKey then
                self, Some coin
            else
                self, keyChain.RewindOutput output
        | _ -> 
            match keyChain.RewindOutput output with
            | Some coin -> self.AddCoin coin, Some coin
            | None -> self, None
