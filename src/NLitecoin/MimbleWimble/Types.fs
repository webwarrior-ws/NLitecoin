namespace NLitecoin.MimbleWimble

open System.IO

open NBitcoin
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters

type ISerializeable =
    abstract Write: BitcoinStream -> unit
    // no Read() method as it will be static method and can't be included in interface

[<AutoOpen>]
module Helpers =
    let write (stream: BitcoinStream) (object: #ISerializeable) =
        assert(stream.Serializing)
        object.Write stream

    let writeUint256 (stream: BitcoinStream) (number: uint256) =
        assert(stream.Serializing)
        number.AsBitcoinSerializable().ReadWrite stream

    let readUint256 (stream: BitcoinStream) : uint256 =
        assert(not stream.Serializing)
        let tempValue = uint256.MutableUint256()
        tempValue.ReadWrite stream
        tempValue.Value

    let writeBigInt (stream: BitcoinStream) (number: bigint) (numBytes: int) =
        assert(stream.Serializing)
        let bytes = number.ToByteArray()
        if bytes.Length < numBytes then
            stream.ReadWrite (Array.append (Array.zeroCreate numBytes) bytes |> ref)
        elif bytes.Length > numBytes then
            failwithf "Requested to write %d bytes, but number has %d bytes" numBytes bytes.Length
        else
            stream.ReadWrite (bytes |> ref)

    let readBigInt (stream: BitcoinStream) (numBytes: int) : bigint =
        assert(not stream.Serializing)
        let result : ref<array<uint8>> = Array.zeroCreate numBytes |> ref
        stream.ReadWrite result
        bigint result.Value

    let readArray<'T> (stream: BitcoinStream) (readFunc : BitcoinStream -> 'T) : array<'T> =
        let len = int <| NBitcoin.Protocol.VarInt.StaticRead stream
        Array.init len (fun _ -> readFunc stream)

    let writeArray<'T when 'T :> ISerializeable> (stream: BitcoinStream) (arr: array<'T>) =
        let len = uint64 arr.Length
        NBitcoin.Protocol.VarInt.StaticWrite(stream, len)
        for each in arr do
            each.Write stream

type BlindingFactor = 
    | BlindindgFactor of uint256
    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | BlindindgFactor number -> number |> writeUint256 stream
        
    static member Read(stream: BitcoinStream) : BlindingFactor =
        BlindindgFactor(readUint256 stream)

type Hash = 
    | Hash of uint256
    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | Hash number -> number |> writeUint256 stream
        
    static member Read(stream: BitcoinStream) : Hash =
        readUint256 stream |> Hash

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
        let writer = new BitcoinStream(stream, true)
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

    static member Read(stream: BitcoinStream) =
        PedersenCommitment(readBigInt stream PedersenCommitment.NumBytes)

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | PedersenCommitment number -> writeBigInt stream number PedersenCommitment.NumBytes

type PublicKey = 
    | PublicKey of bigint
    static member NumBytes = 33

    static member Read(stream: BitcoinStream) =
        PublicKey(readBigInt stream PublicKey.NumBytes)

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | PublicKey number -> writeBigInt stream number PublicKey.NumBytes

type Signature = 
    | Signature of bigint
    static member NumBytes = 64

    static member Read(stream: BitcoinStream) =
        Signature(readBigInt stream Signature.NumBytes)

    interface ISerializeable with
        member self.Write(stream) =
            match self with
            | Signature number -> writeBigInt stream number Signature.NumBytes

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
    static member Read(stream: BitcoinStream) : Input =
        assert(not stream.Serializing)
        let featuresByte = ref 0uy
        stream.ReadWrite featuresByte
        let features = featuresByte.Value |> int |> enum<InputFeatures>
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

        result

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

type OutputMessageStandardFields =
    {
        KeyExchangePubkey: PublicKey
        ViewTag: uint8
        MaskedValue: uint64
        MaskedNonce: bigint
    }
    static member MaskedNonceNumBytes = 16

type OutputMessage =
    {
        Features: OutputFeatures
        StandardFields: Option<OutputMessageStandardFields>
        ExtraData: array<uint8>
    }
    static member Read(stream: BitcoinStream) : OutputMessage =
        assert(not stream.Serializing)

        let featuresByte = ref 0uy
        stream.ReadWrite featuresByte
        let features = featuresByte.Value |> int |> enum<OutputFeatures>
        
        let standardFields =
            if int(features &&& OutputFeatures.STANDARD_FIELDS_FEATURE_BIT) <> 0 then
                let pubKey = PublicKey.Read stream
                let viewTag = ref 0uy
                stream.ReadWrite viewTag
                let maskedValue = ref 0UL
                stream.ReadWrite maskedValue
                let maskedNonce = readBigInt stream OutputMessageStandardFields.MaskedNonceNumBytes
                {
                    KeyExchangePubkey = pubKey
                    ViewTag = viewTag.Value
                    MaskedValue = maskedValue.Value
                    MaskedNonce = maskedNonce
                }
                |> Some
            else
                None

        let extraData =
            if int(features &&& OutputFeatures.EXTRA_DATA_FEATURE_BIT) <> 0 then
                let data = ref Array.empty<uint8>
                stream.ReadWrite data
                data.Value
            else
                Array.empty

        let result = 
            {
                Features = features
                StandardFields = standardFields
                ExtraData = extraData
            }

        result

    interface ISerializeable with
        member self.Write(stream) = 
            assert(stream.Serializing)
            
            stream.ReadWrite(self.Features |> uint8) |> ignore

            if int(self.Features &&& OutputFeatures.STANDARD_FIELDS_FEATURE_BIT) <> 0 then
                let fields = self.StandardFields.Value
                write stream fields.KeyExchangePubkey
                stream.ReadWrite fields.ViewTag |> ignore
                stream.ReadWrite fields.MaskedValue |> ignore
                writeBigInt stream fields.MaskedNonce OutputMessageStandardFields.MaskedNonceNumBytes

            if int(self.Features &&& OutputFeatures.EXTRA_DATA_FEATURE_BIT) <> 0 then
                stream.ReadWrite(ref self.ExtraData)

type RangeProof(bytes: array<uint8>) =
    do assert(bytes.Length <= 675)

    member _.Data = bytes

    static member Read(stream: BitcoinStream) : RangeProof =
        assert(not stream.Serializing)
        let result = ref Array.empty<uint8>
        stream.ReadWrite result
        RangeProof result.Value

    interface ISerializeable with
        member self.Write(stream) = 
            assert(not stream.Serializing)
            stream.ReadWrite(ref bytes)

type Output =
    {
        Commitment: PedersenCommitment
        SenderPublicKey: PublicKey
        ReceiverPublicKey: PublicKey
        Message: OutputMessage
        RangeProof: RangeProof
        Signature: Signature
    }
    static member Read(stream: BitcoinStream) : Output =
        raise <| System.NotImplementedException()

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

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
    static member Read(stream: BinaryReader) : PegOutCoin =
        raise <| System.NotImplementedException()

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

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
    static member Read(stream: BitcoinStream) : Kernel =
        raise <| System.NotImplementedException()

    interface ISerializeable with
        member self.Write(stream) = raise <| System.NotImplementedException()

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
    static member Read(stream: BitcoinStream) : TxBody =
        {
            Inputs = readArray stream Input.Read
            Outputs = readArray stream Output.Read
            Kernels = readArray stream Kernel.Read
        }

    interface ISerializeable with
        member self.Write(stream) = 
            writeArray stream self.Inputs
            writeArray stream self.Outputs
            writeArray stream self.Kernels

type Transaction =
    {
        // The kernel "offset" k2 excess is k1G after splitting the key k = k1 + k2.
        KernelOffset: BlindingFactor
        StealthOffset: BlindingFactor
        // The transaction body.
        Body: TxBody
    }
    static member ParseString(txString: string) : Transaction =
        let encoder = NBitcoin.DataEncoders.HexEncoder()
        let binaryTx = encoder.DecodeData txString
        let reader = new BitcoinStream(binaryTx)
        Transaction.Read reader

    static member Read(stream: BitcoinStream) : Transaction =
        let result =
            {
                KernelOffset = BlindingFactor.Read stream
                StealthOffset = BlindingFactor.Read stream
                Body = TxBody.Read stream
            }
        
        result

    interface ISerializeable with
        member self.Write(stream) = 
            self.KernelOffset |> write stream
            self.StealthOffset |> write stream
            self.Body |> write stream
