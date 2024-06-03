import { createWalletClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts'
import { mainnet } from 'viem/chains';
import { http } from 'viem';
import SpaceAndTimeSDK from '../src/SpaceAndTimeSDK';

describe('SpaceAndTimeSDK with Viem', () => {
  it('should initialize SDK with Viem', async () => {
    // well-known private key for testing
    const privateKey = '0xb6b08906be38f1bb2148ff77738b079165d5b0ac78be875c914534bc9b44d88f';

    const account = privateKeyToAccount(privateKey);

    const client = createWalletClient({
      account,
      chain: mainnet,
      transport: http(),
    });

    const signer = {
      getAddress: () => Promise.resolve(client.account.address),
      signMessage: (message: string) => client.account.signMessage({ message }),
    };
    expect(client.account.address).toBe((await client.getAddresses())[0]);
    
    const config = {
      signer: signer,
      baseUrl: 'https://api.spaceandtime.app/v1', 
      userId: 'instruxi-001', 
      joinCode: '', 
      scheme: '1', 
      authType: 'user' // can be `user` or `wallet`, 
    };

    // Call the init method with the real configuration
    const sdk = await SpaceAndTimeSDK.init(config);

    // Assert that the SDK instance is created with the correct properties
    expect(sdk).toBeInstanceOf(SpaceAndTimeSDK);
    expect(sdk.baseUrl).toBe(config.baseUrl);
    expect(sdk.userId).toBe(config.userId);
    expect(sdk.joinCode).toBe(config.joinCode);
    expect(sdk.scheme).toBe(config.scheme);
    expect(sdk.authType).toBe(config.authType);
    expect(sdk.session).toBeUndefined();
    expect(sdk.publicKey).toBe(client.account.address);

    const testMessage = "test message"
    const signableTestMessage = {
      account: client.account, // or another suitable account
      message: testMessage
    };
    expect(await sdk.signer.signMessage(testMessage)).toBe(await client.signMessage(signableTestMessage));

    if ('getAddress' in sdk.signer) {
      expect(await sdk.signer.getAddress()).toBe(client.account.address);
    }
    const auth = await sdk.authenticate();
    const authSuccess = auth[0]?.accessToken ? true : false;
    expect(authSuccess).toBe(true);

  });
});