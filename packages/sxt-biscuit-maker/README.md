## SxT Biscuit Maker

This is a utility to make biscuits for the SxT tables. The utility is written in TypeScript and is compiled to JavaScript.

## Installation

```bash
  npm install @instruxi-io/sxt-biscuit-maker
```

## Dependencies 


This library is only tested with ED25519 private key pairs. SxT Typescript SDK contains a ED25519Wallet helper or you may optionally bring your own keys.


```javascript
import { ED25519Wallet } from '@instruxi-io/sxt-typescript-sdk';

const tableKeys = new ED25519Wallet();
const keyData = tableKeys.generateKeyPairEncodings();

console.log(`Public Key: ${keyData.hexEncodedPublicKey}`);
console.log(`Private Key (abbrev): ${keyData.hexEncodedPrivateKey.substring(0, 10)}`);
```

## Usage

Typescript 

```typescript
import BiscuitMaker from '@instruxi-io/sxt-biscuit-maker';

const biscuitMaker = BiscuitMaker.init();

await biscuitMaker.generateTableBiscuits("EXAMPLE_SCHEMA.EXAMPLE_TABLE", biscuitMaker, privateKey);
```

Javascript 

```javascript
const BiscuitMaker = require('@instruxi-io/sxt-biscuit-maker');

const biscuitMaker = BiscuitMaker.init();

await biscuitMaker.generateTableBiscuits("EXAMPLE_SCHEMA.EXAMPLE_TABLE", biscuitMaker, privateKey);
```

## Development

### 1.) Install dependencies
```bash
  pnpm install
```

### 2.) Build
```bash
  pnpm build
```

### 3.) Test
```bash
  pnpm test
```

Note: This package is published to GitHub Package Registry. Please refer to the [GitHub Package Registry documentation](https://help.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages) for more information.

## Contributors

- [Austin Przybysz](https://github.com/austpryb)
