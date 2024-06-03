import * as nacl from 'tweetnacl';
import { encode as encodeB64, decode as decodeB64 } from '@stablelib/base64';
import { randomBytes } from 'crypto';

export interface KeyPairEncodings {
    ED25519PublicKeyUint: Uint8Array;
    ED25519PrivateKeyUint: Uint8Array;
    b64PublicKey: string;
    b64PrivateKey: string;
    hexEncodedPublicKey: string;
    hexEncodedPrivateKey: string;
}

export default class ED25519Signer {
    public keyPair: nacl.SignKeyPair;

    constructor(privateKeyBase64?: string) {
        if (privateKeyBase64) {
            let privateKey = decodeB64(privateKeyBase64);
            this.keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
        } else {
            this.keyPair = nacl.sign.keyPair();
        }
    }

    static fromSeed(seed: string): ED25519Signer {
        const keyPair = nacl.sign.keyPair.fromSeed(new TextEncoder().encode(seed));
        return new ED25519Signer(encodeB64(keyPair.secretKey));
    }

    get getAddress(): Uint8Array {
        return this.keyPair.publicKey;
    }

    get privateKey(): Uint8Array {
        return this.keyPair.secretKey;
    }

    signMessage(message: string): string {
        const messageUint8 = new TextEncoder().encode(message);
        const signature = nacl.sign.detached(messageUint8, this.keyPair.secretKey);
        return encodeB64(signature);
    }

    static verify(message: string, signature: string, publicKey: Uint8Array): boolean {
        const messageUint8 = new TextEncoder().encode(message);
        const signatureUint8 = decodeB64(signature);
        return nacl.sign.detached.verify(messageUint8, signatureUint8, publicKey);
    }

    toObject(): string {
        const keyPairEncodings = this.generateKeyPairEncodings();
        return JSON.stringify({
            ED25519PublicKeyUint: keyPairEncodings.ED25519PublicKeyUint,
            ED25519PrivateKeyUint: keyPairEncodings.ED25519PrivateKeyUint,
            b64PublicKey: keyPairEncodings.b64PublicKey,
            b64PrivateKey: keyPairEncodings.b64PrivateKey,
            hexEncodedPublicKey: keyPairEncodings.hexEncodedPublicKey,
            hexEncodedPrivateKey: keyPairEncodings.hexEncodedPrivateKey
        });
    }

    static fromJSON(json: string): ED25519Signer {
        const obj = JSON.parse(json);
        return new ED25519Signer(obj.b64PrivateKey);
    }
    
    static generateRandomWallet(): ED25519Signer {
        const seed = randomBytes(32);
        return this.fromSeed(encodeB64(seed));
    }

    generateKeyPairEncodings(): KeyPairEncodings {
        const keyPair = this.keyPair
    
        const ED25519PublicKeyUint = keyPair.publicKey;
        const ED25519PrivateKeyUint = keyPair.secretKey.slice(0, 32); 
    
        const b64PublicKey = Buffer.from(ED25519PublicKeyUint).toString('base64');
        const b64PrivateKey = Buffer.from(ED25519PrivateKeyUint).toString('base64');
        const hexEncodedPublicKey = Buffer.from(ED25519PublicKeyUint).toString("hex");
        const hexEncodedPrivateKey = Buffer.from(ED25519PrivateKeyUint).toString("hex");

        return {
          ED25519PublicKeyUint,
          ED25519PrivateKeyUint,
          b64PublicKey,
          b64PrivateKey,
          hexEncodedPublicKey,
          hexEncodedPrivateKey
        };
    }
}