module NLitecoin.MimbleWimble.Tests

open System

open NUnit.Framework

open NLitecoin.MimbleWimble

[<SetUp>]
let Setup () =
    ()

[<Test>]
let ParsePegInTransaction () =
    let rawTransaction = IO.File.ReadAllText "transaction1.txt"

    (*
    "amount": 0.00000000,
    "fee": -0.00036500,
    "confirmations": 0,
    "trusted": false,
    "txid": "70343498d773fc60b8384d55020fca3e13b6bf7ceb292989ffe760ed11bd029a",
    "walletconflicts": [
    ],
    "time": 1691399426,
    "timereceived": 1691399426,
    "bip125-replaceable": "unknown",
    "details": [
    {
        "address": "tmweb1qqgcvx65rq4mhay4yzljtu3ct2xryxdd5d3y932jlp0mk9rvdv3glzqjv92v527qw83as4amsd5wywtzh3n0j2f6tzd8xeckdlmmmp0ye0g0gf6ul",
        "category": "send",
        "amount": -10.00000000,
        "label": "mimblewimble",
        "mweb_out": "f6d714abd6d50a746abebb169bcbe39caa0ad73acb54f2f4a61b6c3d909cb38e",
        "fee": -0.00036500,
        "abandoned": false
    },
    {
        "address": "tmweb1qqgcvx65rq4mhay4yzljtu3ct2xryxdd5d3y932jlp0mk9rvdv3glzqjv92v527qw83as4amsd5wywtzh3n0j2f6tzd8xeckdlmmmp0ye0g0gf6ul",
        "category": "receive",
        "amount": 10.00000000,
        "label": "mimblewimble",
        "mweb_out": "f6d714abd6d50a746abebb169bcbe39caa0ad73acb54f2f4a61b6c3d909cb38e"
    }
    ],
    *)

    let transaction = Transaction.ParseString rawTransaction

    ()
