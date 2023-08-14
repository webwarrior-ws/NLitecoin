module NLitecoin.MimbleWimble.TransactionBuilder

open NBitcoin


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

let private CreateInputs (inputCoins: seq<NLitecoin.MimbleWimble.Coin>) : Inputs =
    let blinds, keys, inputs =
        [| for inputCoin in inputCoins do
            let blind = Pedersen.BlindSwitch inputCoin.Blind.Value inputCoin.Amount
            let ephemeralKey = NBitcoin.RandomUtils.GetUInt256()
            let input = 
                Input.Create 
                    inputCoin.OutputId 
                    (Pedersen.Commit inputCoin.Amount blind) 
                    ephemeralKey 
                    inputCoin.SpendKey.Value
            () |]
        |> Array.unzip3

    failwith "not implemented"
