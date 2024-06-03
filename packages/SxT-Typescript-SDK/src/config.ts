export async function signMessage(wallet: { signMessage: (args: { message: string }) => Promise<string> }, message: string) {
    return await wallet.signMessage({ message });
}

export async function getAddress(wallet: { getAddresses: () => Promise<string[]> }) {
    const [account] = await wallet.getAddresses();
    return account;
}