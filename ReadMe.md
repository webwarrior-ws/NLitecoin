NLitecoin
---------

This library aims to be a .NETStandard2.0 nuget package that:
- Is consumable from .NET6.0 or newer.
- Is written in F#.
- Is a better alternative to [NBitcoin.Altcoins' Litecoin](https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin.Altcoins/Litecoin.cs) API & features.
- NOTE: NLitecoin will depend on NBitcoin's nuget package to reuse bitcoin logic, but it will not depend on NBitcoin.Altcoins.

Roadmap:
- Milestone1: Feature parity with NBitcoin.Altcoin's Litecoin utility (no need to reach 100% compatibility, just enough to make it work in geewallet).
- Milestone2: MimbleWimble support.
