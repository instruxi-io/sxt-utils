function checkStringFormat(userString) {
    if(userString == undefined || userString.length === 0 || userString == null) {
        throw new Error('Empty String provided.')
    }
    else if(typeof userString !== 'string') {
        throw new Error(`Expected a String but got ${typeof userString} `)
    }
}

function checkArrayFormat(userArray){
  if(!Array.isArray(userArray)) {
    throw new Error(`Expected an array but got ${typeof userArray}`)
  }
}

function isBase64(str) {
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*?(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

    if (!base64Regex.test(str)) {
      throw new Error("String is not base64 encoded");
    }

    return true;
  }

function checkResourceIdFormat (resourceId) {
    const parts = resourceId.split('.');
    if (parts.length !== 2) {
        throw error(`Expected a string in the format 'schema.table' but got ${resourceId}`);
    }
}

function isHexString(str) {
    return /^[0-9a-fA-F]+$/.test(str);
}

function checkBooleanFormat(userBoolean) {
    if(typeof userBoolean !== 'boolean') {
        throw new Error(`Expected a boolean but got ${typeof userBoolean}`)
    }
}

function checkResourceIdFormat (resourceId) {
    const parts = resourceId.split('.');
    if (parts.length !== 2) {
        throw error(`Expected a string in the format 'schema.table' but got ${resourceId}`);
    }
}

let Utils = {
    checkStringFormat,
    checkResourceIdFormat,
    checkArrayFormat,
    checkBooleanFormat,
    isBase64,
    isHexString,
    checkResourceIdFormat
}

export default Utils;
