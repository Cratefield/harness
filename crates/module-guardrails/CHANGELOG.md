# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- First release, 0.1.0: the policy engine every automated value-moving action must pass. It checks hard denies, recipient and contract allowlists, required simulation and micro-USD caps, and it has a kill switch and an audit trail. It denies by default and fails closed ([#763](https://github.com/Cratefield/harness/issues/763)).
