# Changelog

## [1.1.0](https://github.com/bodgit/rvz/compare/v1.0.3...v1.1.0) (2026-10-13)


### Features

* Add Compress to write RVZ images ([#185](https://github.com/bodgit/rvz/issues/185)) ([afa5890](https://github.com/bodgit/rvz/commit/afa58908a576e265c896fa86c38616b3570dac6f))
* Compress RVZ images with Zstandard ([#187](https://github.com/bodgit/rvz/issues/187)) ([a074c33](https://github.com/bodgit/rvz/commit/a074c333b290774921b28443de10f93dc47945e7))
* Compress Wii partitions with user-supplied keys ([#190](https://github.com/bodgit/rvz/issues/190)) ([92d0218](https://github.com/bodgit/rvz/commit/92d0218e262298c24e28bd583470a8607c0d67ff))
* Store empty and repeated chunks once ([#188](https://github.com/bodgit/rvz/issues/188)) ([d5485ac](https://github.com/bodgit/rvz/commit/d5485acb7a5c9c5b7ae944a05ffd06277ae18fc2))
* Store padding as seeds when compressing ([#189](https://github.com/bodgit/rvz/issues/189)) ([640e8b5](https://github.com/bodgit/rvz/commit/640e8b5a2d6f887cba02f9da76b9c7192d47ba6c))
* Support hash exceptions ([#175](https://github.com/bodgit/rvz/issues/175)) ([a56c3b2](https://github.com/bodgit/rvz/commit/a56c3b2df86fed4e212c2c9c9734f9981659f67b))


### Bug Fixes

* Cast uint32 to int64 prior to overflow ([#130](https://github.com/bodgit/rvz/issues/130)) ([a70f2cb](https://github.com/bodgit/rvz/commit/a70f2cb5099183a5a4091723c64fe1b73e4201aa))
* **deps:** Migrate to urfave/cli v3 ([#180](https://github.com/bodgit/rvz/issues/180)) ([ebb28e2](https://github.com/bodgit/rvz/commit/ebb28e2349754809e3959b6d2eea5955771b6d98))
* **deps:** update module github.com/klauspost/compress to v1.20.1 ([#151](https://github.com/bodgit/rvz/issues/151)) ([7de8095](https://github.com/bodgit/rvz/commit/7de8095d12ff5b8e66ebfff1033c6e23ca4ae959))
* **deps:** update module github.com/klauspost/compress to v1.20.3 ([#186](https://github.com/bodgit/rvz/issues/186)) ([bc43905](https://github.com/bodgit/rvz/commit/bc439051cbedab7fe22a0c73bd2e7f19a310645e))
* **deps:** update module github.com/schollz/progressbar/v3 to v3.19.1 ([#152](https://github.com/bodgit/rvz/issues/152)) ([2ab2da1](https://github.com/bodgit/rvz/commit/2ab2da117eb53abc20270905e003df4cd5ef9de0))
* **deps:** update module github.com/stretchr/testify to v1.12.1 ([#168](https://github.com/bodgit/rvz/issues/168)) ([78b067c](https://github.com/bodgit/rvz/commit/78b067ccd4617833425228627ebe371c906fcf0e))
* **deps:** update module github.com/ulikunitz/xz to v0.5.17 ([#167](https://github.com/bodgit/rvz/issues/167)) ([bcb8d7a](https://github.com/bodgit/rvz/commit/bcb8d7a2441d7f5bef3d0d807b588fbd2fdabb0a))
* **deps:** update module golang.org/x/sync to v0.24.0 ([#154](https://github.com/bodgit/rvz/issues/154)) ([9aa721d](https://github.com/bodgit/rvz/commit/9aa721d82a52af8d9165011458b17d36e5ee75ef))
* Group offset overflow and zstd decoder pooling ([#172](https://github.com/bodgit/rvz/issues/172)) ([949f3bd](https://github.com/bodgit/rvz/commit/949f3bd11c0dec26fd19cba9438e60025fee4f8a))
* Handle empty groups correctly ([#173](https://github.com/bodgit/rvz/issues/173)) ([1b8104d](https://github.com/bodgit/rvz/commit/1b8104db5322f08be613ace1ff5556fad458a20c))
* Tidy up AES ciphers, packed reads and cleanup on error ([#176](https://github.com/bodgit/rvz/issues/176)) ([6e3cf0e](https://github.com/bodgit/rvz/commit/6e3cf0e9ce671ce8f11a288f4f2b39aaffe50836))
* Validate header fields and table entries ([#174](https://github.com/bodgit/rvz/issues/174)) ([7b15b7c](https://github.com/bodgit/rvz/commit/7b15b7c37be62dc1ee925addd37d00c64b082c32))


### Performance Improvements

* Buffer reads of each group ([#181](https://github.com/bodgit/rvz/issues/181)) ([747e733](https://github.com/bodgit/rvz/commit/747e7337120a3a70ed7647324f9d4fd8c115181f))
* Compress in parallel ([#191](https://github.com/bodgit/rvz/issues/191)) ([543ccf6](https://github.com/bodgit/rvz/commit/543ccf610a67f187eea1c99a3631ea3248eff612))
* Decompress raw data areas in parallel ([#184](https://github.com/bodgit/rvz/issues/184)) ([2920898](https://github.com/bodgit/rvz/commit/29208986370b8abdf81ac43a5cc3e98f29428055))
* Generate padding a block at a time ([#182](https://github.com/bodgit/rvz/issues/182)) ([95232b9](https://github.com/bodgit/rvz/commit/95232b9906b5cb0108024e742d00058c88135214))
* Rebuild Wii partition blocks in parallel ([#183](https://github.com/bodgit/rvz/issues/183)) ([90c99e7](https://github.com/bodgit/rvz/commit/90c99e72b281b4f224d9f74b150d5b8581499bd4))
