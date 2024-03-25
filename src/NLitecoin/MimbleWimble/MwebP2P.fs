// MWEB peer-to-peer messages as defined in https://github.com/DavidBurkett/lips/blob/LIP0006/LIP-0006.mediawiki
namespace NLitecoin.MimbleWimble.MwebP2P

open System

open Fsdk.Misc
open NBitcoin
open NBitcoin.Protocol

open NLitecoin.MimbleWimble

/// New message codes to be used as inventory type in getdata requests
module MwebMessageCodes =
    let MSG_MWEB_HEADER = Enum.ToObject(typeof<InventoryType>, 0x20000008) :?> InventoryType
    let MSG_MWEB_LEAFSET = Enum.ToObject(typeof<InventoryType>, 0x20000009) :?> InventoryType

type IUtxo =
    inherit ISerializeable

    abstract member GetOutputID : unit -> Hash

    abstract member LeafIndex: uint64

type FullUtxo(leafIndex: uint64, output: Output) =
    interface IUtxo with
        member self.Write stream = 
            VarInt.StaticWrite(stream, leafIndex)
            (output :> ISerializeable).Write stream
            
        member self.GetOutputID() =
            output.GetOutputID()

        member self.LeafIndex = leafIndex

    static member Read(stream: BitcoinStream) : FullUtxo =
        let leafIndex = VarInt.StaticRead stream
        let output = Output.Read stream
        FullUtxo(leafIndex, output)

/// Same as FullUtxo, but Output stores RangeProof hash instead of RangeProof itself
type CompactUtxo(leafIndex: uint64, output: Output) =
    interface IUtxo with
        member self.Write stream = 
            VarInt.StaticWrite(stream, leafIndex)
            (output :> ISerializeable).Write stream
            
        member self.GetOutputID() : Hash =
            let hasher = Hasher()
            hasher.Append output.Commitment
            hasher.Append output.SenderPublicKey
            hasher.Append output.ReceiverPublicKey
            hasher.Append(Hasher.CalculateHash output.Message)
            hasher.Append output.RangeProof
            hasher.Append output.Signature
            hasher.Hash()

        member self.LeafIndex = leafIndex

    static member Read(stream: BitcoinStream) : CompactUtxo =
        BetterAssert (not stream.Serializing) "stream.Serializing should be false when reading"
        let leafIndex = VarInt.StaticRead stream
        let output =
            {
                Commitment = PedersenCommitment.Read stream
                SenderPublicKey = PublicKey.Read stream
                ReceiverPublicKey = PublicKey.Read stream
                Message = OutputMessage.Read stream
                RangeProof = RangeProof.RangeProof <| (Hash.Read stream).ToBytes()
                Signature = Signature.Read stream
            }
        CompactUtxo(leafIndex, output)

type HashOnlyUtxo(leafIndex: uint64, hash: Hash) =
    interface IUtxo with
        member self.Write stream = 
            VarInt.StaticWrite(stream, leafIndex)
            (hash :> ISerializeable).Write stream

        member self.GetOutputID() = hash

        member self.LeafIndex = leafIndex

    static member Read(stream: BitcoinStream) : HashOnlyUtxo =
        let leafIndex = VarInt.StaticRead stream
        let hash = Hash.Read stream
        HashOnlyUtxo(leafIndex, hash)
    
type MwebOutputFromat =
    | FULL_UTXO = 0x00
    | HASH_ONLY = 0x01
    | COMPACT_UTXO = 0x02

type MwebUtxosRequest =
    {
        BlockHash: uint256
        StartIndex: uint64
        NumRequested: uint16
        OutputFormat: MwebOutputFromat
    }
    interface ISerializeable with
        member self.Write stream = 
            BetterAssert stream.Serializing "stream.Serializing should be true when writing"

            self.BlockHash |> WriteUint256 stream
            VarInt.StaticWrite(stream, self.StartIndex)
            stream.ReadWrite self.NumRequested |> ignore
            stream.ReadWrite(byte self.OutputFormat) |> ignore

    static member Read(stream: BitcoinStream) : MwebUtxosRequest =
        BetterAssert (not stream.Serializing) "stream.Serializing should be false when reading"
        {
            BlockHash = ReadUint256 stream
            StartIndex = VarInt.StaticRead stream
            NumRequested = stream.ReadWrite 0us
            OutputFormat = stream.ReadWrite 0uy |> int32 |> enum
        }

type MwebUtxos<'TMwebUtxo when 'TMwebUtxo :> IUtxo> =
    {
        BlockHash: uint256
        StartIndex: uint64
        Utxos: array<'TMwebUtxo>
        ParentHashes: array<Hash>
    }
    interface ISerializeable with
        member self.Write stream = 
            BetterAssert stream.Serializing "stream.Serializing should be true when writing"

            self.BlockHash |> WriteUint256 stream
            VarInt.StaticWrite(stream, self.StartIndex)
            stream.ReadWrite(byte MwebUtxos<'TMwebUtxo>.OutputFormat) |> ignore
            WriteArray stream self.Utxos
            WriteArray stream self.ParentHashes

    /// Assumes that format has already been read and is used to determine correct value of 'TMwebUtxo type parameter
    static member Read (stream: BitcoinStream) (utxoReadFunction: BitcoinStream -> 'TMwebUtxo) (blockHash: uint256) (startIndex: uint64) : MwebUtxos<'TMwebUtxo> =
        BetterAssert (not stream.Serializing) "stream.Serializing should be false when reading"
        {
            BlockHash = blockHash
            StartIndex = startIndex
            Utxos = ReadArray stream utxoReadFunction
            ParentHashes = ReadArray stream Hash.Read
        }

    static member OutputFormat : MwebOutputFromat =
        if typeof<'TMwebUtxo> = typeof<Output> then
            MwebOutputFromat.FULL_UTXO 
        elif typeof<'TMwebUtxo> = typeof<Hash> then
            MwebOutputFromat.HASH_ONLY
        elif typeof<'TMwebUtxo> = typeof<CompactUtxo> then
            MwebOutputFromat.COMPACT_UTXO
        else
            failwithf "Unsupported MWEB Utxo type: %A" typeof<'TMwebUtxo>

type HogExAndMwebHeader =
    {
        Merkle: MerkleBlock
        HogEx: NBitcoin.Transaction
        MwebHeader: MwebBlockHeader
    }
    interface ISerializeable with
        member self.Write stream = 
            BetterAssert stream.Serializing "stream.Serializing should be true when writing"

            stream.ReadWrite self.Merkle |> ignore
            stream.ReadWrite self.HogEx |> ignore
            self.MwebHeader |> Write stream

    static member Read(stream: BitcoinStream) : HogExAndMwebHeader =
        BetterAssert (not stream.Serializing) "stream.Serializing should be false when reading"
        let dummyMerkleRef : MerkleBlock = null
        let dummyHogExRef : NBitcoin.Transaction = null
        {
            Merkle = stream.ReadWrite dummyMerkleRef
            HogEx = stream.ReadWrite dummyHogExRef
            MwebHeader = MwebBlockHeader.Read stream
        }
    
type MwebLeafset =
    {
        BlockHash: uint256
        /// Serialized in big-endian form
        Leafset: Collections.BitArray
    }
    interface ISerializeable with
        member self.Write stream = 
            self.BlockHash |> WriteUint256 stream
            let numBitsInByte = 8
            let bytes = Array.zeroCreate ((self.Leafset.Count - 1) / numBitsInByte + 1)
            self.Leafset.CopyTo(bytes, 0)
            bytes |> Array.rev |> WriteByteArray stream

    static member Read(stream: BitcoinStream) : MwebLeafset =
        {
            BlockHash = ReadUint256 stream
            Leafset = ReadByteArray stream |> Array.rev |> Collections.BitArray
        }

type MwebHeaderPayload() =
    inherit Payload()
    let mutable header : Option<HogExAndMwebHeader> = None

    member self.Header = header.Value

    override self.Command = "mwebheader"

    override self.ReadWriteCore(stream) =
        if stream.Serializing then
            Write stream header.Value
        else
            header <- Some(HogExAndMwebHeader.Read stream)

type MwebLeafsetPayload() =
    inherit Payload()
    let mutable leafset : Option<MwebLeafset> = None

    member self.Leafset = leafset.Value

    override self.Command = "mwebleafset"

    override self.ReadWriteCore(stream) =
        if stream.Serializing then
            Write stream leafset.Value
        else
            leafset <- Some(MwebLeafset.Read stream)

type GetMwebUtxosPayload(request: MwebUtxosRequest) =
    inherit Payload()

    member self.Request = request

    override self.Command = "getmwebutxos"

    override self.ReadWriteCore(stream) =
        if stream.Serializing then
            Write stream request
        else
            failwith "not supported"

type MwebUtxosPayload() =
    inherit Payload()
    let mutable mwebUtxos : Option<ISerializeable> = None

    member self.GetMwebUtxos<'TMwebUtxo when 'TMwebUtxo :> IUtxo>() : MwebUtxos<'TMwebUtxo> = 
        mwebUtxos.Value :?> MwebUtxos<'TMwebUtxo>

    override self.Command = "mwebutxos"

    override self.ReadWriteCore(stream) =
        if stream.Serializing then
            Write stream mwebUtxos.Value
        else
            let blockHash = ReadUint256 stream
            let startIndex = VarInt.StaticRead stream
            let format = stream.ReadWrite 0uy |> int32 |> enum<MwebOutputFromat>
            let utxos =
                match format with
                | MwebOutputFromat.FULL_UTXO -> 
                    MwebUtxos<FullUtxo>.Read stream FullUtxo.Read blockHash startIndex :> ISerializeable
                | MwebOutputFromat.HASH_ONLY -> 
                    MwebUtxos<HashOnlyUtxo>.Read stream HashOnlyUtxo.Read blockHash startIndex :> ISerializeable
                | MwebOutputFromat.COMPACT_UTXO -> 
                    MwebUtxos<CompactUtxo>.Read stream CompactUtxo.Read blockHash startIndex :> ISerializeable
                | _ -> failwithf "Incorrect MWEB output serialization format: %A" format
            mwebUtxos <- Some utxos
