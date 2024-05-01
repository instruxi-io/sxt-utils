## SxT Biscuit Maker

This is a utility to make biscuits for the SxT tables. The utility is written in TypeScript and is compiled to JavaScript.

## Installation

```bash
  npm install @instruxi-io/sxt-biscuit-maker
```

Note: This package is published to GitHub Package Registry. Please refer to the [GitHub Package Registry documentation](https://help.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages) for more information.


## Usage

```typescript
import  BiscuitMaker  from '@instruxi-io/sxt-biscuit-maker';

const biscuitMaker = BiscuitMaker.init();

// expects json file with table keys
const tableKeys = "./EXAMPLE_SCHEMA.EXAMPLE_TABLE.json";

await biscuits.generateTableBiscuits("EXAMPLE_SCHEMA.EXAMPLE_TABLE", BiscuitMaker, tableKeys);
```


```javascript
const BiscuitMaker = require('@instruxi-io/sxt-biscuit-maker');

const biscuitMaker = BiscuitMaker.init();

// expects json file with table keys
const tableKeys = "./EXAMPLE_SCHEMA.EXAMPLE_TABLE.json";

await biscuits.generateTableBiscuits("EXAMPLE_SCHEMA.EXAMPLE_TABLE", BiscuitMaker, tableKeys);
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


## License
Yet to be updated

## Contributors

- [Austin Przybysz](https://github.com/austpryb)
