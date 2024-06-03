import { privateKeyToAccount } from 'viem/accounts'
import SpaceAndTimeSDK from './packages/sxt-typescript-sdk-viem/src/SpaceAndTimeSDK';

const privateKey = '0xb6b08906be38f1bb2148ff77738b079165d5b0ac78be875c914534bc9b44d88f';

const account = privateKeyToAccount(privateKey);

const signer = {
    getAddress: async () => account.address,
    signMessage: (message: string) => account.signMessage({ message }),
};

const config = {
    signer: signer,
    baseUrl: 'https://api.spaceandtime.app/v1',
    userId: 'instruxi-001',
    joinCode: '',
    scheme: '1',
    authType: 'user',
  };

async function initSDK() {
  const sdk = await SpaceAndTimeSDK.init(config);
  console.log(await sdk.authenticate())
}

initSDK();