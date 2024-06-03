import { AxiosResponse } from 'axios';

export type AuthTypes = 'wallet' | 'user';

export interface SessionData {
	accessToken: string;
	refreshToken: string;
	accessTokenExpires: number;
	refreshTokenExpires: number;
}

// accept viem and ethers
export interface MinimalSigner {
    getAddress: () => Promise<string>;
    signMessage: (message: string) => Promise<string>;
}

export interface Config {
    signer: MinimalSigner;
    baseUrl: string;
    userId: string;
    joinCode: string;
    scheme: string;
    authType: string;
    session?: SessionData;
}  

export interface HttpSuccess {
    data: any;
    status: number;
    statusText: string;
    headers: any;
    config: any;
    request?: any;
    authCode?: string;
  }

export interface HttpError<T = any> extends Error {
    config: any;
    code?: string;
    request?: any;
    response?: AxiosResponse<T>;
}

interface ABI {
    constant?: boolean;
    inputs: {
      name: string;
      type: string;
      indexed?: boolean;
    }[];
    name?: string;
    outputs?: {
      name: string;
      type: string;
    }[];
    payable: boolean;
    stateMutability: string;
    type: string;
    anonymous?: boolean;
}

export interface IndexingRequest {
    namespace: string;
    contractName: string;
    abi: ABI[];
}

interface Input {
    name: string;
    internalType: string;
    type: string;
    indexed: boolean;
}

interface Output {
    name: string;
    indexed: boolean;
}

export interface EventTransaction {
    name: string;
    type: string;
    anonymous: boolean;
    stateMutability: string;
    payable: boolean;
    constant: boolean;
    inputs: Input[];
    outputs: Output[];
}
