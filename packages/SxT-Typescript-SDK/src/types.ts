import { AxiosResponse } from 'axios';
import ED25519Wallet from "./ED25519Wallet";
import {ethers} from "ethers";

export type AuthTypes = 'wallet' | 'user';



export interface SessionData {
	accessToken: string;
	refreshToken: string;
	accessTokenExpires: number;
	refreshTokenExpires: number;
}

export interface Config {
	signer: ethers.Wallet | ED25519Wallet;
	baseUrl: string;
	userId: string;
	joinCode: string;
	scheme: string;
	authType?: string;
	session?: SessionData
}

export interface HttpSuccess<T = any> {
    data: T;
    status: number;
    statusText: string;
    headers: any;
    config: any;
    request?: any;
}

export interface HttpError<T = any> extends Error {
    config: any;
    code?: string;
    request?: any;
    response?: AxiosResponse<T>;
}

export interface AuthCodeData {
    authCode: string;
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
