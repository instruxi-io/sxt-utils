import axios, { AxiosResponse } from 'axios';
import { Buffer } from 'buffer';
import { Utils } from './utils/utils-functions';
import {MinimalSigner} from './types';
import {
	HttpSuccess,
	HttpError,
	IndexingRequest,
	EventTransaction,
	Config,
	SessionData
} from './types';

export default class SpaceAndTimeSDK implements Config {
    signer: MinimalSigner;
    baseUrl: string;
    userId: string;
    joinCode: string;
    scheme: string;
    authType: string;
    publicKey?: string;
    session?: SessionData;
  
    constructor({ signer, baseUrl, userId, joinCode, scheme, authType, session }: Config) {
      this.baseUrl = baseUrl;
      this.signer = signer;
      this.userId = userId;
      this.joinCode = joinCode;
      this.scheme = scheme;
      this.authType = authType;
      this.session = session;
    }

    static async init(config: Config): Promise<SpaceAndTimeSDK> {
        const instance = new SpaceAndTimeSDK(config);
        await instance.getPublicKey();
        return instance;
    }
      
    async isSessionExpired(): Promise<boolean> {
        if (!this.session) {
            return false;
        }
        return Date.now() > this.session.accessTokenExpires;
    }

    private async checkSession(): Promise<SessionData | false> {
        if (!this.session || await this.isSessionExpired()) {
            return false;
        }
        return this.session;
    }

    private async getPublicKey(): Promise<void> {
        try {
            this.publicKey = await this.signer.getAddress();
        } catch (error) {
            console.error(error);
        }
    }
    
    async signMessage(message: string): Promise<string> {
       try {
          return await this.signer.signMessage(message);
        } catch (error){
          throw new Error(error instanceof Error ? error.message : "An unknown error occurred");
        }
    }

    async generateUserAuthCode(prefix?: string): Promise<[string | null, string | null]> {
        try {
          const payload = { userId: this.userId, prefix: prefix, joinCode: this.joinCode };
          const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/auth/code`, payload);
          if (response.data.authCode) {
            return [response.data.authCode, null];
          } else {
            return [null, "Response data is undefined"];
          }
        } catch (error) {
          const err = error as Error;
          console.error(err);
          return [null, err.message];
        }
    }

    async generateWalletAuthCode(prefix?: string): Promise<[string | null, string | null]> {
        try {
          const payload = { walletAddr: this.publicKey, userId: this.userId, prefix: prefix, joinCode: this.joinCode };
          const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/auth/wallet/code`, payload);
          if (response.data.authCode) {
            return [response.data.authCode, null];
          } else {
            return [null, "Response data is undefined"];
          }
        } catch (error) {
          const err = error as Error;
          console.error(err);
          return [null, err.message];
        }
    }

    async checkUserId(): Promise<[HttpSuccess | null, null | HttpError ]> {
        try {
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/auth/idexists/${this.userId}`);
            return [response.data, null];
        } catch (error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async validateAccessToken(): Promise<[HttpSuccess | null, HttpError | null]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            const config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken
                }
            };

            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/auth/validtoken`, config);
            return [response.data, null];
        } catch (error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async assertCheckUserId(): Promise<boolean | null> {
        try {
            let [userIdResponse, userIdError]= await this.checkUserId();
            if (userIdError) throw new Error(userIdError.message);
            return userIdResponse ? true : false;
        } catch (error) {
            return null;
        }
    }

    async generateSignature(message: string): Promise<string> {
        try {
            return await this.signer.signMessage(message);
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : "An unknown error occurred");
        }
    }

    async generateAuthToken(authCode: string, signature: string): Promise<SessionData | null> {
        try {
          const payload = {
            userId: this.userId,
            authCode,
            signature,
            key: this.publicKey,
            scheme: this.scheme,
          };
          const response: AxiosResponse = await axios.post(`${this.baseUrl}/auth/token`, payload);
          if (response.status !== 200) {
            console.error(`Request failed with status code ${response.status}`);
            return null;
          }
          const { accessToken, refreshToken, accessTokenExpires, refreshTokenExpires } = response.data;
          return { accessToken, refreshToken, accessTokenExpires, refreshTokenExpires };
        } catch (error) {
          const err = error as Error;
          console.error(err);
          return null;
        }
    }

    async authenticate(prefix: string = ""): Promise<[SessionData | null, HttpError | null]> {
        try {
            let authCodeResponse, authCodeError;
            if (this.authType === "wallet") {
                [authCodeResponse, authCodeError] = await this.generateWalletAuthCode(prefix);
            } else if (this.authType === "user") {
                [authCodeResponse, authCodeError] = await this.generateUserAuthCode(prefix);
            } else {
                return [null, { name: 'Error', message: 'Invalid authType provided', config: {} }];
            }

            if (authCodeError || !authCodeResponse) {
                console.error(authCodeError);
                return [null, { name: 'Error', message: `Failed to generate ${this.authType} auth token`, config: {} }];
            }

            const signature = await this.signer.signMessage(authCodeResponse);
            const sessionData = await this.generateAuthToken(authCodeResponse, signature);

            if (!sessionData) {
                return [null, { name: 'Error', message: 'Failed to generate auth token', config: {} }];
            }

            this.session = sessionData;
            return [sessionData, null];
        } catch (error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    public base64ToUint8(base64PrivateKey: string, base64PublicKey: string): Uint8Array {
        Utils.isBase64(base64PrivateKey);
        Utils.isBase64(base64PublicKey);

        let privateKeyBuffer = Buffer.from(base64PrivateKey, 'base64');
        let publicKeyBuffer = Buffer.from(base64PublicKey, 'base64');

        let privateKeyUint8 = new Uint8Array(privateKeyBuffer.buffer, privateKeyBuffer.byteOffset, privateKeyBuffer.byteLength);
        let publicKeyUint8 = new Uint8Array(publicKeyBuffer.buffer, publicKeyBuffer.byteOffset, publicKeyBuffer.byteLength);

        let combinedPrivateKey: number[] = [];

        if(privateKeyUint8.length === publicKeyUint8.length) {
            for(let idx = 0; idx < privateKeyUint8.length; idx++) {
                combinedPrivateKey[idx] = privateKeyUint8[idx];
            }

            for(let idx = 0; idx < publicKeyUint8.length; idx++) {
                combinedPrivateKey[privateKeyUint8.length + idx] = publicKeyUint8[idx];
            }
        }

        let combinedPrivateKeyUint8 = new Uint8Array(combinedPrivateKey);

        return combinedPrivateKeyUint8;
    }

    async refreshToken(refreshToken?: string): Promise<[SessionData | null, null | HttpError ]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            refreshToken = refreshToken || session.refreshToken;

            if (!refreshToken) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Refresh token is not provided',
                    config: {},
                };
                return [null, error];
            }

            const response = await axios.post(`${this.baseUrl}/auth/refresh`, null, {
                headers: {
                    Authorization : `Bearer ${refreshToken}`
                }
            });

            const { accessToken, refreshToken: newRefreshToken, accessTokenExpires, refreshTokenExpires } = response.data;

            if (!newRefreshToken) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Refresh token is not provided',
                    config: {},
                };
                return [null, error];
            }

            this.session = { accessToken, refreshToken: newRefreshToken, accessTokenExpires, refreshTokenExpires }
            return [{ accessToken, refreshToken: newRefreshToken, accessTokenExpires, refreshTokenExpires }, null];
        } catch (error) {
            const httpError: HttpError = {
                name: 'Error',
                message: typeof error === 'string' ? error : 'Unknown error',
                config: {},
            };
            return [null, httpError];
        }
    }

    async logout(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            const response = await axios.post(`${this.baseUrl}/auth/logout`, null, {
                headers: {
                    Authorization : `Bearer ${session.refreshToken}`
                }
            });

            return [response, null];
        } catch (error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    private updateUrlVersion(apiUrl: string): string {
        const newVersion: string = "v2"
        const urlParts: string[] = apiUrl.split("/")
        urlParts[urlParts.length-1] = newVersion
        return urlParts.join("/");
    }

    async getSchemas(scope: string = "", schema: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let v2versionURL: string = this.updateUrlVersion(this.baseUrl);

            let endpoint: string | null = null;

            if(scope == "" && schema == "") {
                endpoint = `${v2versionURL}/discover/schema`;
            }
            else if(scope != "" && schema == "") {
                endpoint = `${v2versionURL}/discover/schema?scope=${scope}`;
            }
            else {
                scope = scope.toUpperCase();
                schema = schema.toUpperCase();
                endpoint = `${v2versionURL}/discover/schema?scope=${scope}&searchPattern=${schema}`
            }

            Utils.checkApiVersion(endpoint);

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }

            const response: AxiosResponse = await axios.get(endpoint, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getTables(scope: string, schema: string, table: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
            let endpoint: string | null = null;

            scope = scope.toUpperCase();
            schema = schema.toUpperCase();

            if(table == "") {
                endpoint = `${v2versionURL}/discover/table?scope=${scope}&schema=${schema}`
            }
            else {
                table = table.toUpperCase();
                endpoint = `${v2versionURL}/discover/table?scope=${scope}&schema=${schema}&searchPattern=${table}`
            }

            Utils.checkApiVersion(endpoint);

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }

            const response: AxiosResponse = await axios.get(endpoint, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    private async discoveryAPIRequest(schema: string, tableName: string, endpoint: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            Utils.checkApiVersion(endpoint);
            schema = schema.toUpperCase();
            tableName = tableName.toUpperCase();

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            };

            const response: AxiosResponse = await axios.get(endpoint, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getTableColumns(schema: string, tableName: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/table/column?schema=${schema}&table=${tableName}`;
        return await this.discoveryAPIRequest(schema, tableName, endpoint);
    }

    async getTableIndexes(schema: string, tableName: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/table/index?schema=${schema}&table=${tableName}`;
        return await this.discoveryAPIRequest(schema, tableName, endpoint);
    }

    async getPrimaryKeys(schema: string, tableName: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/table/primaryKey?schema=${schema}&table=${tableName}`;
        return await this.discoveryAPIRequest(schema, tableName, endpoint);
    }

    private async discoveryAPIReferencesRequest(schema: string, tableName: string, column: string, endpoint: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            Utils.checkApiVersion(endpoint);
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            schema = schema.toUpperCase();
            tableName = tableName.toUpperCase();
            column = column.toUpperCase();

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            };

            const response: AxiosResponse = await axios.get(endpoint, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getPrimaryKeyReferences(schema: string, tableName: string, column: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/refs/primarykey?schema=${schema}&table=${tableName}&column=${column}`;
        return await this.discoveryAPIReferencesRequest(schema, tableName, column, endpoint);
    }

    async getForeignKeyReferences(schema: string, tableName: string, column: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/refs/foreignkey?schema=${schema}&table=${tableName}&column=${column}`;
        return await this.discoveryAPIReferencesRequest(schema, tableName, column, endpoint);
    }

    async getTableRelationships(schema: string, scope: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            schema = schema.toUpperCase();
            scope = scope.toUpperCase();

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            };

            const response: AxiosResponse = await axios.get(`${v2versionURL}/discover/table/relations?scope=${scope}&schema=${schema}`, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    private async blockchainDataAPIRequest(url: string, chainId: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            Utils.checkApiVersion(url);
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            if (chainId !== "") {
                Utils.checkStringFormat(chainId);
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken
                }
            };

            let response: AxiosResponse = await axios.get(url, config);
            return [response, null];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getBlockchains(): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/blockchains`;
        return await this.blockchainDataAPIRequest(endpoint);
    }

    async getBlockchainSchemas(chainId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/blockchains/${chainId}/schemas`;
        return await this.blockchainDataAPIRequest(endpoint, chainId);
    }

    async getBlockchainInformation(chainId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        let v2versionURL: string = this.updateUrlVersion(this.baseUrl);
        let endpoint: string = `${v2versionURL}/discover/blockchains/${chainId}/meta`;
        return await this.blockchainDataAPIRequest(endpoint, chainId);
    }

    public addSecuritySuffix(sqlText: string, publicKey: string, accessType: string): string {
        return sqlText + " WITH \"public_key=" + publicKey + ",access_type=" + accessType + "\""
    }

    // SQL API
    async createSchema(sqlText: string, biscuitTokens: string[] = [], originApp: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            Utils.checkArrayFormat(biscuitTokens);
            sqlText = sqlText.toUpperCase();
            if (!this.session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not initialized',
                    config: {},
                };
                return [null, error];
            }
            const payload = {
                biscuits: biscuitTokens,
                sqlText: sqlText
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + this.session.accessToken,
                    originApp: originApp
                }
            }

            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/sql/ddl`, payload, config);
            return [ response.data, null ];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async createTable(sqlText: string, biscuitTokens: string[] = [], originApp: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let payload = {
                biscuits: biscuitTokens,
                sqlText: sqlText,
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    originApp: originApp
                }
            }

            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/sql/ddl`, payload, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async DDL(sqlText: string, biscuitTokens: string[] = [], originApp: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let payload = {
                biscuits: biscuitTokens,
                sqlText: sqlText.toUpperCase(),
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    originApp: originApp
                }
            }

            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/sql/ddl`, payload, config);
            return [ response.data, null ];
        }

        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async DML(resources: string[], sqlText: string, biscuitTokens: string[] = [], originApp: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let payload = {
                biscuits: biscuitTokens,
                resources: resources,
                sqlText: sqlText
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    originApp: originApp
                }
            }

            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/sql/dml`, payload, config);
            return [ response.data, null ];
        }

        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async DQL(resources: string[], sqlText: string, biscuitTokens: string[] = [], originApp: string = "", rowCount: number = 0): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let payload = {};
            if(rowCount > 0) {
                payload = {
                    biscuits: biscuitTokens,
                    resources:resources,
                    sqlText: sqlText,
                    rowCount: rowCount
                }
            }
            else {
                payload = {
                    biscuits: biscuitTokens,
                    resources: resources,
                    sqlText: sqlText
                }
            }

            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    originApp: originApp
                }
            }
            let response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/sql/dql`, payload, config);
            return [ response, null ];
        }
        catch(error) {
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async executeView(viewName: string, parametersRequest: { name: string, type: string }[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let paramEndPoint = "";
            let paramString = "";
            let apiEndPoint =`${this.baseUrl}/sql/views/${viewName}`

            if(Object.keys(parametersRequest).length > 0) {
                for(const { name,type } of parametersRequest) {
                    paramString += `${name}=${type}&`
                }

                paramString = paramString.slice(0, paramString.length - 1);
                paramEndPoint += `?params=${paramString}`;
            }
            apiEndPoint += paramEndPoint;
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.get(apiEndPoint, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async queryViewById(viewId: string, parameters: any, biscuits: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                parameters: parameters,
                viewId: viewId,
                biscuits: biscuits
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sql/view/query`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async refreshMaterializedView(viewId: string, biscuits: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                viewId: viewId,
                biscuits: biscuits
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sql/view/materialized/refresh`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getMaterializedViewLastRefreshTime(viewId: string, biscuits: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                viewId: viewId,
                biscuits: biscuits
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sql/view/materialized/last-refreshed`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async executeContentQuery(query: any, biscuits: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                query: query,
                biscuits: biscuits
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sql/content-queries`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    // Encryption API
    async EncryptedDQL(resources: string[], sqlText: string, biscuitTokens: string[] = [], originApp: string = "", rowCount: number = 0): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                resources: resources,
                sqlText: sqlText,
                rowCount: rowCount,
                biscuits: biscuitTokens,
                originApp: originApp
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/encryption/sql/dql`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async EncryptedDML(resources: string[], sqlText: string, biscuitTokens: string[] = [], originApp: string = ""): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                resources: resources,
                sqlText: sqlText,
                biscuits: biscuitTokens,
                originApp: originApp
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/encryption/sql/dml`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async configureEncryption(tables: { resourceId: string, columns: { encType: string, encOption: string, name: string }[] }[], biscuitTokens: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                tables: tables,
                biscuits: biscuitTokens
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/encryption/configure`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    // Tamper Proof DQL
    async executeTamperproofQuery(sqlText: string, biscuits: string[] = []): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            }
            const data = {
                sqlText: sqlText,
                biscuits: biscuits
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sql/tamperproof-query`, data, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }
    // Subscription Management API
    async getSubscriptionInfo(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/subscription`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getSubscriptionUsers(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/subscription/users`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async setSubscriptionName(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.put(`${this.baseUrl}/v1/subscription/name`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async createSubscriptionInvite(role: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/subscription/invite?role=${role}`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async joinSubscription(joinCode: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/subscription/invite/${joinCode}`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async setUserRole(userId: string, role: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/subscription/setrole/${userId}?role=${role}`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async removeUser(userId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/subscription/remove/${userId}`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async leaveSubscription(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                }
            }
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/subscription/leave`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    // Smart Contract Indexing API
    async getSupportedBlockchains(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/sci/supported-chains`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getSubscriptionIndexedContracts(): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/sci/subscription-contracts`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getSmartContractSchemas(chainId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/sci/${chainId}/schemas`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getIndexedSmartContracts(chainId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/sci/${chainId}/indexed-contracts`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getSmartContractInfo(chainId: string, contractAddress: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sci/${chainId}/contract/${contractAddress}/info`, {}, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async requestSmartContractIndexing(chainId: string, contractAddress: string, indexingRequest: IndexingRequest): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sci/${chainId}/contract/${contractAddress}/index`, indexingRequest, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getSmartContractEventTransactions(chainId: string, contractAddress: string, event: string, eventTransactions: EventTransaction[]): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/sci/${chainId}/contract/${contractAddress}/transactions-for-event/${event}`, eventTransactions, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async getInfrastructureGroup(groupId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json',
                    'biscuit': 'test'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.get(`${this.baseUrl}/v1/streaming/group/${groupId}`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async createInfrastructureGroup(groupId: string, publicKey: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json',
                    'biscuit': 'test'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.post(`${this.baseUrl}/v1/streaming/group/${groupId}`, { publicKey }, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }

    async deleteInfrastructureGroup(groupId: string): Promise<[HttpSuccess | null, null | HttpError]> {
        try {
            const session = await this.checkSession();
            if (!session) {
                const error: HttpError = {
                    name: 'Error',
                    message: 'Session is not valid',
                    config: {},
                };
                return [null, error];
            }
            let config = {
                headers: {
                    Authorization: 'Bearer ' + session.accessToken,
                    'Content-Type': 'application/json',
                    'biscuit': 'test'
                }
            };
            const response: AxiosResponse<HttpSuccess> = await axios.delete(`${this.baseUrl}/v1/streaming/group/${groupId}`, config);
            return [ response.data, null ];
        }
        catch(error){
            const httpError: HttpError = {
                name: 'Error',
                message: error instanceof Error ? error.message : 'An unknown error occurred',
                config: {},
            };
            return [null, httpError];
        }
    }
}
