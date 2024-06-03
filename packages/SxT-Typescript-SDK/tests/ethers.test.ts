import { ethers } from 'ethers';
import SpaceAndTimeSDK from '../src/SpaceAndTimeSDK';

describe('SpaceAndTimeSDK with ethers', () => {
  it('should initialize SDK with a real ethers wallet', async () => {
    // well-known private key for testing
    const privateKey = '0xbb911d4d69d8f089fd660ec238950c4c5c922ba90f606927063d991e46f06e78';

    const wallet = new ethers.Wallet(privateKey);

    const signer = {
      getAddress: () => Promise.resolve(wallet.address),
      signMessage: (message: string) => wallet.signMessage(message),
    };

    expect(wallet.address).toBe(await wallet.getAddress());
    
    const config = {
      signer: signer,
      baseUrl: 'https://api.spaceandtime.app/v1',
      userId: 'ethers-test',
      joinCode: '',
      scheme: '1', 
      authType: 'wallet', 
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
    expect(sdk.publicKey).toBe(wallet.address);

    const testMessage = "test message"
    expect(await sdk.signer.signMessage(testMessage)).toBe(await wallet.signMessage(testMessage));

    if ('getAddress' in sdk.signer) {
      expect(await sdk.signer.getAddress()).toBe(wallet.address);
    }
    const auth = await sdk.authenticate();
    const authSuccess = auth[0]?.accessToken ? true : false;
    expect(authSuccess).toBe(true);
    
  });
});