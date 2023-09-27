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

let ValidateKernelSumForTransaction (transaction: Transaction) =
    let inputCommits = transaction.Body.Inputs |> Array.map (fun input -> input.Commitment)
    let outputCommits = transaction.Body.Outputs |> Array.map (fun output -> output.Commitment)
    let kernelCommits = transaction.Body.Kernels |> Array.map (fun kernel -> kernel.Excess)
    let coinsAdded = transaction.Body.Kernels |> Array.sumBy (fun kernel -> kernel.GetSupplyChange())

    
    // Calculate UTXO nonce sum
    let sumUtxoCommitment = 
        Pedersen.AddCommitments 
            outputCommits 
            (Array.append inputCommits [| Pedersen.Commit (abs coinsAdded) (BlindingFactor NBitcoin.uint256.Zero) |])

    failwith "not yet implemented"
    (*
    // Calculate total kernel excess
    Commitment sum_excess_commitment = Pedersen::AddCommitments(kernel_commits);
    if (!offset.IsZero()) {
        sum_excess_commitment = Pedersen::AddCommitments(
            { sum_excess_commitment, Commitment::Blinded(offset, 0) }
        );
    }

    if (sum_utxo_commitment != sum_excess_commitment) {
        LOG_ERROR_F(
            "UTXO sum {} does not match kernel excess sum {}.",
            sum_utxo_commitment,
            sum_excess_commitment
        );
        ThrowValidation(EConsensusError::BLOCK_SUMS);
    }
    *)
