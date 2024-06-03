import { createWalletClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts'
import { mainnet } from 'viem/chains';
import { http } from 'viem';
import SpaceAndTimeSDK from '../src/SpaceAndTimeSDK';

describe('SpaceAndTimeSDK with Viem', () => {
  it('should initialize SDK with Viem', async () => {
    // well-known private key for testing
    const privateKey = '0x4d34fe9f545c5003bb23f74607d619f3365c75f01eff922e7262cb09d0553030';

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
      userId: 'viem-test', 
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