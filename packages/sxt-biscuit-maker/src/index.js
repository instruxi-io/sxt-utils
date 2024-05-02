import { biscuit, block, authorizer, Biscuit, KeyPair, Fact, PrivateKey, BiscuitBuilder } from '@biscuit-auth/biscuit-wasm';
import Utils from './utils/utils.js';
import { webcrypto } from 'node:crypto'

if (typeof globalThis.crypto === 'undefined' || Object.getOwnPropertyDescriptor(globalThis, 'crypto')?.writable) {
  globalThis.crypto = webcrypto;
}

const SQLCommandType = {
    DDL: "ddl",
    DML: "dml",
    DQL: "dql",
  };

class SQLOperation {
    constructor(type, value) {
      this.CommandType = type;
      this.Value = value;
    }
  }

SQLOperation.CREATE = new SQLOperation(SQLCommandType.DDL, "ddl_create");
SQLOperation.ALTER = new SQLOperation(SQLCommandType.DDL, "ddl_alter");
SQLOperation.DROP = new SQLOperation(SQLCommandType.DDL, "ddl_drop");
SQLOperation.INSERT = new SQLOperation(SQLCommandType.DML, "dml_insert");
SQLOperation.UPDATE = new SQLOperation(SQLCommandType.DML, "dml_update");
SQLOperation.MERGE = new SQLOperation(SQLCommandType.DML, "dml_merge");
SQLOperation.DELETE = new SQLOperation(SQLCommandType.DML, "dml_delete");
SQLOperation.SELECT = new SQLOperation(SQLCommandType.DQL, "dql_select");

Object.freeze(SQLOperation);

export default class BiscuitMaker {
    constructor() {
        this.SQLOperation = SQLOperation;
        this._biscuits = {}
    }

    static init() {
        return new BiscuitMaker();
    }

    generateTableBiscuits = async (resourceId, biscuitMaker, hexEncodedPrivateKey) => {
        try {
            Utils.checkResourceIdFormat(resourceId)
    
            if (Utils.isHexString(hexEncodedPrivateKey)){
                biscuitMaker = biscuitMaker.init()
                let dml = biscuitMaker.buildBiscuit(hexEncodedPrivateKey, [resourceId], false, ["INSERT", "UPDATE", "MERGE", "DELETE", "SELECT"])
                let ddl = biscuitMaker.buildBiscuit(hexEncodedPrivateKey, [resourceId], false, ["CREATE", "DROP", "SELECT"])
                let dql = biscuitMaker.buildBiscuit(hexEncodedPrivateKey, [resourceId], false, ["SELECT"])
                let admin = biscuitMaker.buildBiscuit(hexEncodedPrivateKey, [resourceId], false, ["CREATE", "DROP", "INSERT", "UPDATE", "MERGE", "DELETE", "SELECT"])
                let wildcard = biscuitMaker.buildBiscuit(hexEncodedPrivateKey, [resourceId], true, ["CREATE", "DROP", "INSERT", "UPDATE", "MERGE", "DELETE", "SELECT"])
                let result = { dml, ddl, dql, admin, wildcard}
                this._biscuits = result
                return true;
            } else {
                throw new Error("Invalid hex encoded private key");
            }
        } catch (error) {
            throw new Error(`Failed to generate table biscuits: ${error.message}`);
        }
    }

    buildBiscuit = (privateKey, resourceIds, wildCardRequired = false, operations = []) => {
        try {
            Utils.checkStringFormat(privateKey)
            Utils.checkArrayFormat(resourceIds)
            Utils.checkBooleanFormat(wildCardRequired)
            Utils.checkArrayFormat(operations);

            let resourceIdsContainer = resourceIds.map(resourceId => resourceId.toLowerCase())

            if(wildCardRequired) {
                    for(let resourceId of resourceIdsContainer) {
                        let biscuitBuilder = biscuit``;
                        let wildcard = '*'

                        let biscuitBlock = block`sxt:capability(${wildcard},${resourceId})`
                        biscuitBuilder.merge(biscuitBlock)

                        let wildCardBiscuitToken = biscuitBuilder.build(PrivateKey.fromString(privateKey)).toBase64();
                        return wildCardBiscuitToken;
                    }
                }

            else {

                let biscuitOperations = {
                    "CREATE" : SQLOperation.CREATE.Value,
                    "ALTER" : SQLOperation.ALTER.Value,
                    "DROP": SQLOperation.DROP.Value,
                    "INSERT": SQLOperation.INSERT.Value,
                    "UPDATE": SQLOperation.UPDATE.Value,
                    "MERGE": SQLOperation.MERGE.Value,
                    "DELETE": SQLOperation.DELETE.Value,
                    "SELECT": SQLOperation.SELECT.Value
                }

                let sqlOperations = [];
                for(let operation of operations) {
                    sqlOperations.push(biscuitOperations[operation])
                }

                for(let resourceId of resourceIdsContainer) {
                    let biscuitBuilder = biscuit``;
                    for(let operation of sqlOperations) {
                        let biscuitBlock = block`sxt:capability(${operation}, ${resourceId})`
                        biscuitBuilder.merge(biscuitBlock)
                    }
                    let biscuitToken = biscuitBuilder.build(PrivateKey.fromString(privateKey)).toBase64()
                    return biscuitToken;
                }
            }
        }
        catch(error) {
            return error;
        }
    }

}
