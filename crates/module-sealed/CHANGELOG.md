# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- First release, 0.1.0: the server half of client-side sealed blobs. It stores the ciphertext the `@cratefield/sealed` client produces under a server outer wrap, serves it back byte-identical, erases it by crypto-shredding, and has no server-side recovery path ([#757](https://github.com/Cratefield/harness/issues/757)).
