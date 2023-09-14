module NLitecoin.MimbleWimble.TransactionBuilder

open System

open NBitcoin
open Org.BouncyCastle.Math

type private Inputs =
    {
        TotalBlind: BlindingFactor
        TotalKey: uint256
        Inputs: array<Input>
    }

type private Outputs =
    {
        TotalBlind: BlindingFactor
        TotalKey: uint256
        Outputs: array<Output>
        Coins: array<NLitecoin.MimbleWimble.Coin>
    }

/// Creates a standard input with a stealth key (feature bit = 1)// Creates a standard input with a stealth key (feature bit = 1)
let private CreateInput (outputId: Hash) (commitment: PedersenCommitment) (inputKey: uint256) (outputKey: uint256) =
    let features = InputFeatures.STEALTH_KEY_FEATURE_BIT

    let inputPubKey = PublicKey(inputKey.ToBytes() |> BigInt)
    let outputPubKey = PublicKey(outputKey.ToBytes() |> BigInt)

    // Hash keys (K_i||K_o)
    let keyHasher = Hasher()
    keyHasher.Append inputPubKey
    keyHasher.Append outputPubKey
    let keyHash = keyHasher.Hash().ToUint256().ToBytes()

    // Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
    let sigKey = 
        BigInteger(outputKey.ToBytes())
            .Multiply(BigInteger keyHash)
            .Add(BigInteger(inputKey.ToBytes()))

    let msgHasher = Hasher()
    //msgHasher.Append features
    msgHasher.Append outputId
    let msgHash = msgHasher.Hash().ToUint256().ToBytes()

    let schnorrSignature = EC.SchnorrSign (sigKey.ToByteArrayUnsigned()) msgHash
        
    {
        Features = features
        OutputID = outputId
        Commitment = commitment
        InputPublicKey = Some inputPubKey
        OutputPublicKey = outputPubKey
        Signature = Signature(schnorrSignature.ToBytes() |> BigInt)
        ExtraData = Array.empty
    }

let private CreateInputs (inputCoins: seq<NLitecoin.MimbleWimble.Coin>) : Inputs =
    let blinds, keys, inputs =
        [| for inputCoin in inputCoins do
            let blind = Pedersen.BlindSwitch inputCoin.Blind.Value inputCoin.Amount
            let ephemeralKey = NBitcoin.RandomUtils.GetUInt256()
            let input = 
                CreateInput
                    inputCoin.OutputId 
                    (Pedersen.Commit inputCoin.Amount blind) 
                    ephemeralKey 
                    inputCoin.SpendKey.Value
            yield blind, (BlindingFactor ephemeralKey, BlindingFactor inputCoin.SpendKey.Value), input |]
        |> Array.unzip3

    let positiveKeys, negativeKeys = Array.unzip keys

    {
        TotalBlind = Pedersen.AddBlindingFactors blinds Array.empty
        TotalKey = (Pedersen.AddBlindingFactors positiveKeys negativeKeys).ToUInt256()
        Inputs = inputs
    }

let private CreateOutput (senderPrivKey: uint256) (receiverAddr: StealthAddress) (value: uint64) : Output * BlindingFactor =
        let features = OutputFeatures.STANDARD_FIELDS_FEATURE_BIT

        // Generate 128-bit secret nonce 'n' = Hash128(T_nonce, sender_privkey)
        let n = 
            let hasher = Hasher(HashTags.NONCE)
            hasher.Write(senderPrivKey.ToBytes())
            hasher.Hash().ToUint256().ToBytes()
            |> Array.take 16
            |> BigInt

        // Calculate unique sending key 's' = H(T_send, A, B, v, n)
        let s =
            let hasher = Hasher(HashTags.SEND_KEY)
            hasher.Append receiverAddr.ScanPubKey
            hasher.Append receiverAddr.SpendPubKey
            hasher.Write (BitConverter.GetBytes value)
            hasher.Append n
            hasher.Hash().ToUint256().ToBytes()
            |> BigInteger

        let A =
            match receiverAddr.ScanPubKey with
            | PublicKey pubKey -> BigInteger pubKey.Data

        let B =
            match receiverAddr.SpendPubKey with
            | PublicKey pubKey -> BigInteger pubKey.Data

        // Derive shared secret 't' = H(T_derive, s*A)
        let sA = A.Multiply s
        let t = 
            let hasher = Hasher(HashTags.DERIVE)
            hasher.Write(sA.ToByteArrayUnsigned())
            hasher.Hash()

        // Construct one-time public key for receiver 'Ko' = H(T_outkey, t)*B
        let Ko = 
            let hasher = Hasher(HashTags.OUT_KEY)
            hasher.Append t
            B.Multiply(hasher.Hash().ToUint256().ToBytes() |> BigInteger);

        // Key exchange public key 'Ke' = s*B
        let Ke = B.Multiply s

        // Calc blinding factor and mask nonce and amount.
        let mask = OutputMask.FromShared(t.ToUint256())
        let blind = Pedersen.BlindSwitch mask.PreBlind (int64 value)
        let mv = mask.MaskValue value
        let mn = mask.MaskNonce n

        // Commitment 'C' = r*G + v*H
        let outputCommit = Pedersen.Commit (int64 value) blind

        // Calculate the ephemeral send pubkey 'Ks' = ks*G
        let Ks = Secp256k1.ECPubKey.Create(senderPrivKey.ToBytes())

        // Derive view tag as first byte of H(T_tag, sA)
        let viewTag = 
            let hasher = Hasher(HashTags.TAG)
            hasher.Write(sA.ToByteArrayUnsigned())
            hasher.Hash().ToUint256().ToBytes().[0]

        let message = 
            {
                Features = features
                StandardFields = 
                    Some {
                        KeyExchangePubkey = PublicKey(Ke.ToByteArrayUnsigned() |> BigInt)
                        ViewTag = viewTag
                        MaskedValue = mv
                        MaskedNonce = mn
                    }
                ExtraData = Array.empty
            }

        let rangeProof = 
            let emptyProofMessage = Array.zeroCreate 20
            
            let messageSerialized =
                use memoryStream = new System.IO.MemoryStream()
                let stream = new BitcoinStream(memoryStream, true)
                (message :> ISerializeable).Write stream
                memoryStream.ToArray()

            Bulletproof.ConstructRangeProof 
                value 
                (blind.ToUInt256()) 
                (NBitcoin.RandomUtils.GetUInt256())
                (NBitcoin.RandomUtils.GetUInt256())
                (emptyProofMessage)
                (Some messageSerialized)

        failwith "not implemented"

let private CreateOutputs (recipients: seq<Recipient>) : Outputs =
    let outputBlinds, outputs, coins = 
        [| for recipient in recipients do
            let ephemeralKey = NBitcoin.RandomUtils.GetUInt256()
            let output, rawBlind = CreateOutput ephemeralKey recipient.Address (uint64 recipient.Amount)
            let outputBlind = Pedersen.BlindSwitch rawBlind recipient.Amount
            let coin =
                { Coin.Empty with
                    Blind = Some rawBlind
                    Amount = recipient.Amount
                    OutputId = output.GetOutputID()
                    SenderKey = Some ephemeralKey
                    Address = Some recipient.Address
                }
            yield outputBlind, output, coin
        |]
        |> Array.unzip3

    let outputKeys = 
        coins 
        |> Array.choose (fun coin -> coin.SenderKey)
        |> Array.map BlindingFactor

    {
        TotalBlind = Pedersen.AddBlindingFactors outputBlinds Array.empty
        TotalKey = (Pedersen.AddBlindingFactors outputKeys Array.empty).ToUInt256()
        Outputs = outputs
        Coins = coins
    }
