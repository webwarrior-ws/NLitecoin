module NLitecoin.MimbleWimble.Validation

open NUnit.Framework

open NLitecoin.MimbleWimble

let ValidateTransactionBody (txBody: TxBody) =
    CollectionAssert.IsOrdered txBody.Inputs
    CollectionAssert.IsOrdered txBody.Outputs
    CollectionAssert.IsOrdered txBody.Kernels

    let spentIds = txBody.Inputs |> Array.map (fun input -> input.OutputID)
    CollectionAssert.AllItemsAreUnique spentIds

    let outputIds = txBody.Outputs |> Array.map Hasher.CalculateHash
    CollectionAssert.AllItemsAreUnique outputIds

    let kernelIds = txBody.Kernels |> Array.map Hasher.CalculateHash
    CollectionAssert.AllItemsAreUnique kernelIds

    use bulletproof = new Secp256k1ZKP.Net.BulletProof()
    for output in txBody.Outputs do
        let commitmentBytes =
            match output.Commitment with
            | PedersenCommitment bigint -> bigint.Data
        let rangeProofBytes =
            match output.RangeProof with
            | RangeProof bytes -> bytes
        let messsageSerialized =
            use memoryStream = new System.IO.MemoryStream()
            let stream = new NBitcoin.BitcoinStream(memoryStream, true)
            (output.Message :> ISerializeable).Write stream
            memoryStream.ToArray()
        
        bulletproof.Verify(commitmentBytes, rangeProofBytes, messsageSerialized)
        |> Assert.IsTrue
