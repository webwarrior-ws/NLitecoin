namespace NLitecoin.MimbleWimble

open System.IO

open NBitcoin
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters

type ISerializeable =
    abstract Write: BinaryWriter -> unit
    // no Read() method as it will be static method and can't be included in interface

type BlindingFactor = 
    | BlindindgFactor of uint256
    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | BlindindgFactor number -> 
                let bytes = number.ToBytes()
                stream.Write(bytes, 0, bytes.Length)
        
    static member Read(stream: BinaryReader) =
        stream.ReadBytes 32 |> uint256 |> BlindindgFactor

type Hash = 
    | Hash of uint256
    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | Hash number -> 
                let bytes = number.ToBytes()
                stream.Write(bytes, 0, bytes.Length)
        
    static member Read(stream: BinaryReader) =
        stream.ReadBytes 32 |> uint256 |> Hash

module internal HashTags =
    let ADDRESS = 'A'
    let BLIND = 'B'
    let DERIVE = 'D'
    let NONCE = 'N'
    let OUT_KEY = 'O'
    let SEND_KEY = 'S'
    let TAG = 'T'
    let NONCE_MASK = 'X'
    let VALUE_MASK = 'Y'

type Hasher(?hashTag: char) =
    let blake3 = Blake3Digest()
    do
        blake3.Init(Blake3Parameters())
        match hashTag with
        | Some tag -> blake3.Update(byte tag)
        | None -> ()

    member _.Write(bytes: array<uint8>) =
        blake3.BlockUpdate(bytes, 0, bytes.Length)

    member self.Append(object: ISerializeable) =
        use stream = new MemoryStream()
        use writer = new BinaryWriter(stream)
        object.Write writer
        self.Write(stream.ToArray())

    member _.Hash() =
        let length = 32
        let bytes = Array.zeroCreate length
        blake3.OutputFinal(bytes, 0, length) |> ignore
        Hash(uint256 bytes)

    static member CalculateHash(object: ISerializeable) =
        let hasher = Hasher()
        hasher.Append object
        hasher.Hash()

type PedersenCommitment = 
    | PedersenCommitment of bigint
    static member NumBytes = 33

    static member Read(stream: BinaryReader) =
        stream.ReadBytes PedersenCommitment.NumBytes |> bigint |> PedersenCommitment

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | PedersenCommitment number -> 
                let bytes = number.ToByteArray()
                for i=0 to PedersenCommitment.NumBytes-bytes.Length do // ?
                    stream.Write 0uy
                stream.Write(bytes, 0, bytes.Length)

type PublicKey = 
    | PublicKey of bigint
    static member NumBytes = 33

    static member Read(stream: BinaryReader) =
        stream.ReadBytes PedersenCommitment.NumBytes |> bigint |> PublicKey

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | PublicKey number -> 
                let bytes = number.ToByteArray()
                for i=0 to PublicKey.NumBytes-bytes.Length do // ?
                    stream.Write 0uy
                stream.Write(bytes, 0, bytes.Length)

type Signature = 
    | Signature of bigint
    static member NumBytes = 64

    static member Read(stream: BinaryReader) =
        stream.ReadBytes PedersenCommitment.NumBytes |> bigint |> Signature

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | Signature number -> 
                let bytes = number.ToByteArray()
                for i=0 to Signature.NumBytes-bytes.Length do // ?
                    stream.Write 0uy
                stream.Write(bytes, 0, bytes.Length)

type InputFeatures =
    | STEALTH_KEY_FEATURE_BIT = 0x01
    | EXTRA_DATA_FEATURE_BIT = 0x02

type OutputFeatures =
    | STANDARD_FIELDS_FEATURE_BIT = 0x01
    | EXTRA_DATA_FEATURE_BIT = 0x02

type Input =
    {
        Features: InputFeatures
        OutputID: Hash
        Commitment: PedersenCommitment
        InputPublicKey: Option<PublicKey>
        OutputPublicKey: PublicKey
        ExtraData: array<uint8>
        Signature: Signature
    }
    static member Read(stream: BinaryReader) : Input =
        let features = stream.ReadByte() |> int |> enum<InputFeatures>
        let outputId = Hash.Read stream
        let commitment = PedersenCommitment.Read stream
        let outputPubKey = PublicKey.Read stream

        let inputPubKey =
            if int(features &&& InputFeatures.STEALTH_KEY_FEATURE_BIT) <> 0 then
                Some <| PublicKey.Read stream
            else
                None

        let extraData =
            if int(features &&& InputFeatures.EXTRA_DATA_FEATURE_BIT) <> 0 then
                // how to read array?
                raise <| System.NotImplementedException()
            else
                Array.empty

        let signature = Signature.Read stream

        let result = 
            {
                Features = features
                OutputID = outputId
                Commitment = commitment
                OutputPublicKey = outputPubKey
                InputPublicKey = inputPubKey
                ExtraData = extraData
                Signature = signature
            }

        let hash = Hash.Read stream

        if hash <> Hasher.CalculateHash result then
            failwith "wrong hash"

        result

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

type OutputMessageStandardFields =
    {
        KeyExchangePubkey: PublicKey
        ViewTag: uint8
        MaskedValue: uint64
        /// 16 bytes
        MaskedNonce: bigint
    }

type OutputMessage =
    {
        Features: OutputFeatures
        StandardFields: Option<OutputMessageStandardFields>
        ExtraData: array<uint8>
    }
    static member Read(stream: BinaryReader) : OutputMessage =
        let features = stream.ReadByte() |> int |> enum<OutputFeatures>
        
        let standardFields =
            if int(features &&& OutputFeatures.STANDARD_FIELDS_FEATURE_BIT) <> 0 then
                {
                    KeyExchangePubkey = PublicKey.Read stream
                    ViewTag = stream.ReadByte()
                    MaskedValue = stream.ReadUInt64()
                    MaskedNonce = stream.ReadBytes 16 |> bigint
                }
                |> Some
            else
                None

        let extraData =
            if int(features &&& OutputFeatures.EXTRA_DATA_FEATURE_BIT) <> 0 then
                // how to read array?
                raise <| System.NotImplementedException()
            else
                Array.empty

        let result = 
            {
                Features = features
                StandardFields = standardFields
                ExtraData = extraData
            }

        let hash = Hash.Read stream

        if hash <> Hasher.CalculateHash result then
            failwith "wrong hash"

        result

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

type RangeProof(bytes: array<uint8>) =
    do assert(bytes.Length <= 675)

    member _.Data = bytes

type Output =
    {
        Commitment: PedersenCommitment
        SenderPublicKey: PublicKey
        ReceiverPublicKey: PublicKey
        Message: OutputMessage
        RangeProof: RangeProof
        Signature: Signature
    }

type KernelFeatures =
    | FEE_FEATURE_BIT = 0x01
    | PEGIN_FEATURE_BIT = 0x02
    | PEGOUT_FEATURE_BIT = 0x04
    | HEIGHT_LOCK_FEATURE_BIT = 0x08
    | STEALTH_EXCESS_FEATURE_BIT = 0x10
    | EXTRA_DATA_FEATURE_BIT = 0x20

module KernelFeatures =
    let ALL_FEATURE_BITS = 
        KernelFeatures.FEE_FEATURE_BIT |||
        KernelFeatures.PEGIN_FEATURE_BIT ||| 
        KernelFeatures.PEGOUT_FEATURE_BIT ||| 
        KernelFeatures.HEIGHT_LOCK_FEATURE_BIT ||| 
        KernelFeatures.STEALTH_EXCESS_FEATURE_BIT ||| 
        KernelFeatures.EXTRA_DATA_FEATURE_BIT

type CAmount = int64

type PegOutCoin =
    {
        Amount: CAmount
        ScriptPubKey: NBitcoin.Script // ?
    }

type Kernel =
    {
        Features: KernelFeatures
        Fee: Option<CAmount>
        Pegin: Option<CAmount>
        Pegouts: array<PegOutCoin>
        LockHeight: Option<int32>
        StealthExcess: Option<PublicKey>
        ExtraData: array<uint8>
        // Remainder of the sum of all transaction commitments. 
        // If the transaction is well formed, amounts components should sum to zero and the excess is hence a valid public key.
        Excess: PedersenCommitment
        // The signature proving the excess is a valid public key, which signs the transaction fee.
        Signature: Signature
    }

/// TRANSACTION BODY - Container for all inputs, outputs, and kernels in a transaction or block.
type TxBody =
    {
        /// List of inputs spent by the transaction.
        Inputs: array<Input>
        /// List of outputs the transaction produces.
        Outputs: array<Output>
        /// List of kernels that make up this transaction.
        Kernels: array<Kernel>
    }

type Transaction =
    {
        // The kernel "offset" k2 excess is k1G after splitting the key k = k1 + k2.
        KernelOffset: BlindingFactor
        StealthOffset: BlindingFactor
        // The transaction body.
        Body: TxBody
    }
