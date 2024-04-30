import { isAddress, getAddress } from 'ethers/lib/utils';
import { SessionData } from '../types';
import * as fs from 'fs';

const VALID_DB_RESOURCE_IDENTIFIER = /^[A-Z_][A-Z0-9_]+$/;
const INVALID_RESOURCEID = "Invalid resourceId";
const DEFAULT_SCHEMA = "PUBLIC";

function checkUserIdFormat(userId: string | number) {
  if (typeof userId !== 'string' && typeof userId !== 'number') {
      throw new Error(`User ID must be a string or a number, but got ${typeof userId}`);
  }
}

function isChecksummed(signature: string) {
  if (isAddress(signature)) {
    const checksummedSignature = getAddress(signature);
    if (checksummedSignature === signature) {
      return true;
    } else {
      throw new Error(`signature is not checksummed: ${signature} -> ${checksummedSignature}`);
    }
  }
  throw new Error(`Signature is not a valid Ethereum address: ${signature}`);
}

function checkScheme(scheme: string) {
  if (scheme !== 'ECDSA' && scheme !== 'RSA') {
      throw new Error(`Scheme must be either ECDSA or RSA, but got ${scheme}`);
  }
}

function checkStringFormat(userString: string) {
  if(userString.length === 0) {
      throw new Error('Empty String provided.')
  }
  else if(typeof userString !== 'string') {
      throw new Error(`Expected a String but got ${typeof userString} `)
  }
}

function checkArrayFormat(userArray: any[]) {
  if(!Array.isArray(userArray)) {
    throw new Error(`Expected an array but got ${typeof userArray}`)
  }
}

function isValidDatabaseIdentifier(input: string) {
  return VALID_DB_RESOURCE_IDENTIFIER.test(input);
}

function checkPostgresIdentifier(resourceId: string): { schemaName: string, tableName: string } {
  const parts = resourceId.toUpperCase().split(".");
  let schemaName: string, tableName: string;
  if (parts.length === 0 || parts.length > 2) {
    throw new Error(`${INVALID_RESOURCEID}: Provided table identifier format is invalid`);
  } else if (parts.length === 1) {
    schemaName = DEFAULT_SCHEMA;
    tableName = parts[0];
  } else {
    schemaName = parts[0];
    tableName = parts[1];
  }
  if (!isValidDatabaseIdentifier(schemaName) || !isValidDatabaseIdentifier(tableName)) {
    throw new Error(`${INVALID_RESOURCEID}: Either schema or table identifier is invalid`);
  }
  return { schemaName, tableName };
}

function checkPostGresIdentifiers(resources: string[]): void {
  const results = [];
  for (let i = 0; i < resources.length; i++) {
    const resourceId = resources[i];
    try {
      const { schemaName, tableName } = checkPostgresIdentifier(resourceId);
      results.push({ schemaName, tableName, valid: true });
    } catch (error) {
      if (error instanceof Error) {
        results.push({ resourceId, error: error.message, valid: false });
      } else {
        results.push({ resourceId, error: 'An error occurred', valid: false });
      }
    }
  }
}

function checkBooleanFormat(userBoolean: boolean) {
  if(typeof userBoolean !== 'boolean') {
      throw new Error(`Expected a boolean but got ${typeof userBoolean}`)
  }
}

function checkIsSameUrl(url1: string, url2: string) {
  return url1 === url2;
}

function checkPrefixAndJoinCode(prefix: string | undefined, joinCode: string | undefined) {
  if ((typeof prefix !== 'string' && typeof prefix !== 'undefined') || (typeof joinCode !== 'string' && typeof joinCode !== 'undefined')) {
    const errorPrefix = typeof prefix === 'string' || typeof prefix === 'undefined' ? '' : `Unexpected type of ${typeof prefix} for prefix`;
    const errorJoinCode = typeof joinCode === 'string' || typeof joinCode === 'undefined' ? '' : `${typeof prefix !== 'string' && typeof prefix !== 'undefined' ? ' and' : null} Unexpected type of ${typeof joinCode} for joinCode`;
    throw new Error(`${errorPrefix}${errorJoinCode}`);
  }
}

function isBase64(str: string) {
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*?(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

  if (!base64Regex.test(str)) {
    throw new Error("String is not base64 encoded");
  }

  return true;
}

function isHexString(str: string) {
  return /^[0-9a-fA-F]+$/.test(str);
}

function checkSignature(signature: string) {
  const regex = /[0-9A-Fa-f]{6}/g;
  return regex.test(signature);
}

function checkApiVersion(url: string) {
  const regex = /\/v\d\//;
  const match = url.match(regex);

  if (!match) {
    throw new Error('No version found in API url');
  }

  const version = match[0];

  if (version !== '/v2/') {
    throw new Error('For this endpoint, The API version must be v2 and not v1.');
  }
}

function  isSessionExpired(session: SessionData): boolean {
  return Date.now() > session.accessTokenExpires;
}

function writeToFile(accessToken: string, refreshToken: string, accessTokenExpires: string, refreshTokenExpires: string): void {
  const fileData = { accessToken, refreshToken, accessTokenExpires, refreshTokenExpires};
  try {
      fs.writeFileSync('session.json', JSON.stringify(fileData, null, 2));
  } catch (err) {
      const error = err as Error;
      throw new Error(error.message);
  }
}

function sessionFromFile(): SessionData {
  if (!fs.existsSync('session.json')) {
      throw new Error("session.json does not exist.");
  }

  const fileContents: string = fs.readFileSync('session.json', 'utf8');
  const sessionData: SessionData = JSON.parse(fileContents);

  if (!fileContents || fileContents === '' || !sessionData || isSessionExpired(sessionData)) {
      throw new Error("session.json is empty, invalid, or access token is expired.");
  }

  return sessionData;
}

export const Utils = {
  checkUserIdFormat,
  checkStringFormat,
  checkArrayFormat,
  checkPostgresIdentifier,
  checkBooleanFormat,
  checkIsSameUrl,
  checkPrefixAndJoinCode,
  checkSignature,
  isBase64,
  isHexString,
  isChecksummed,
  checkScheme,
  checkApiVersion,
  checkPostGresIdentifiers,
  sessionFromFile,
  writeToFile
};
