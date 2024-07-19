# frost-ts

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/zmeyer44/frost-ts/node.js.yml)
![GitHub issues](https://img.shields.io/github/issues/zmeyer44/frost-ts)
![GitHub package.json version](https://img.shields.io/github/package-json/v/zmeyer44/frost-ts)
![GitHub stars](https://img.shields.io/github/stars/zmeyer44/frost-ts)

⚠️ **Be Careful:** This project is in early development and should be used for testing purposes only.

Typescript implementation of `Flexible Round Optimized Schnorr Threshold` (FROST) signatures.

FROST is a threshold multisignature (`t-of-n`), so to create a valid signature you require `t` parties to individually sign and contribute signature shares. These signature shares are then combined into a single schnorr signature which is valid under the joint public key.

## Sponsors

Sponsorship at any level is appreciated and encouraged. Currently this work is supported by [OpenSats](https://opensats.org).

## Usage

### Install

```shell
npm i frost-ts
```

### Example

```typescript
import { Participant } from "frost-ts";

const p1 = new Participant(1, 2, 3);
const p2 = new Participant(2, 2, 3);
const p3 = new Participant(3, 2, 3);

p1.init_keygen();
p2.init_keygen();
p3.init_keygen();

p1.generate_shares();
p2.generate_shares();
p3.generate_shares();

p1.aggregate_shares([p2.shares![p1.index - 1], p3.shares![p1.index - 1]]);
p2.aggregate_shares([p1.shares![p2.index - 1], p3.shares![p2.index - 1]]);
p3.aggregate_shares([p1.shares![p3.index - 1], p2.shares![p3.index - 1]]);
```

## Learn about FROST

- [FROST Paper](https://eprint.iacr.org/2020/852.pdf)
- [Python Implementation](https://github.com/jesseposner/FROST-BIP340)
- [Bitcoin.Review Episode](https://www.youtube.com/watch?v=8nuFt-1SWRI)
