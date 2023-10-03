module NLitecoin.MimbleWimble.Wallet

open System

open NBitcoin

let KeyPurposeMweb = 100

type KeyChain(seed: array<byte>) =
    let masterKey = ExtKey.CreateFromSeed seed
    // derive m/0'
    let accountKey = masterKey.Derive(0, true)
    // derive m/0'/100' (MWEB)
    let chainChildKey = accountKey.Derive(KeyPurposeMweb, true)

    let scanKey = chainChildKey.Derive(0, true).ToBytes() |> BigInt |> PublicKey
    let spendKey = chainChildKey.Derive(1, true).ToBytes() |> BigInt |> PublicKey

    member self.GetStealthAddress(index: uint32) : StealthAddress =
        let spendPubKey = self.GetSpendKey(index).CreatePubKey()
        {
            SpendPubKey = spendPubKey.ToBytes(true) |> BigInt |> PublicKey
            ScanPubKey = spendPubKey.TweakMul(scanKey.ToBytes()).ToBytes(true) |> BigInt |> PublicKey
        }

    member self.GetSpendKey(index: uint32) : Secp256k1.ECPrivKey =
        let mi =
            let hasher = new Hasher(HashTags.ADDRESS)
            hasher.Write(BitConverter.GetBytes index)
            hasher.Append scanKey
            hasher.Hash()
        
        Secp256k1.ECPrivKey.Create(spendKey.ToBytes()).TweakAdd(mi.ToBytes())
