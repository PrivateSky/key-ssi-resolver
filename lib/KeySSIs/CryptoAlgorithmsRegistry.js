const crypto = require("pskcrypto");
const SSITypes = require("./SSITypes");
const algorithms = {};
const defaultAlgorithms = {
    hash: (data) => {
        return defaultAlgorithms.encoding(crypto.hash('sha256', data));
    },
    strongHash: (data) => {
        return defaultAlgorithms.encoding(crypto.hash('sha512', data));
    },
    keyDerivation: (password, iterations) => {
        return crypto.deriveKey('aes-256-gcm', password, iterations);
    },
    encryptionKeyGeneration: () => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        return pskEncryption.generateEncryptionKey();
    },
    encryption: (plainData, encryptionKey, options) => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        return pskEncryption.encrypt(plainData, encryptionKey, options);
    },
    decryption: (encryptedData, decryptionKey, authTagLength, options) => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        const utils = require("swarmutils");
        if (!$$.Buffer.isBuffer(decryptionKey) && (decryptionKey instanceof ArrayBuffer || ArrayBuffer.isView(decryptionKey))) {
            decryptionKey = utils.ensureIsBuffer(decryptionKey);
        }
        if (!$$.Buffer.isBuffer(encryptedData) && (decryptionKey instanceof ArrayBuffer || ArrayBuffer.isView(decryptionKey))) {
            encryptedData = utils.ensureIsBuffer(encryptedData);
        }
        return pskEncryption.decrypt(encryptedData, decryptionKey, 16, options);
    },
    encoding: (data) => {
        return crypto.pskBase58Encode(data);
    },
    decoding: (data) => {
        return crypto.pskBase58Decode(data);
    },
    keyPairGenerator: () => {
        return crypto.createKeyPairGenerator();
    }

};

function CryptoAlgorithmsRegistry() {
}


const registerCryptoFunction = (keySSIType, vn, algorithmType, cryptoFunction) => {
    if (typeof algorithms[keySSIType] !== "undefined" && typeof algorithms[vn] !== "undefined" && typeof algorithms[vn][algorithmType] !== "undefined") {
        throw Error(`A ${algorithmType} is already registered for version ${vn}`);
    }

    if (typeof algorithms[keySSIType] === "undefined") {
        algorithms[keySSIType] = {};
    }

    if (typeof algorithms[keySSIType][vn] === "undefined") {
        algorithms[keySSIType][vn] = defaultAlgorithms;
    }
    algorithms[keySSIType][vn][algorithmType] = cryptoFunction;
};

const getCryptoFunction = (keySSI, algorithmType) => {
    let cryptoFunction;
    try {
        cryptoFunction = algorithms[keySSI.getTypeName()][keySSI.getVn()][algorithmType];
    } catch (e) {
        cryptoFunction = defaultAlgorithms[algorithmType];
    }

    if (typeof cryptoFunction === "undefined") {
        throw Error(`Algorithm type <${algorithmType}> not recognized for <${keySSI.getIdentifier(true)}>`);
    }
    return cryptoFunction;
};


CryptoAlgorithmsRegistry.prototype.registerHashFunction = (keySSIType, vn, hashFunction) => {
    registerCryptoFunction(keySSIType, vn, 'hash', hashFunction);
};

CryptoAlgorithmsRegistry.prototype.getHashFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'hash');
};

CryptoAlgorithmsRegistry.prototype.registerStrongHashFunction = (keySSIType, vn, strongHashFunction) => {
    registerCryptoFunction(keySSIType, vn, 'strongHash', strongHashFunction);
};

CryptoAlgorithmsRegistry.prototype.getStrongHashFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'strongHash');
};

CryptoAlgorithmsRegistry.prototype.registerKeyDerivationFunction = (keySSIType, vn, keyDerivationFunction) => {
    registerCryptoFunction(keySSIType, vn, 'keyDerivation', keyDerivationFunction);
};

CryptoAlgorithmsRegistry.prototype.getKeyDerivationFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'keyDerivation');
};

CryptoAlgorithmsRegistry.prototype.registerEncryptionFunction = (keySSIType, vn, encryptionFunction) => {
    registerCryptoFunction(keySSIType, vn, 'encryption', encryptionFunction);
};

CryptoAlgorithmsRegistry.prototype.getEncryptionFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'encryption');
};

CryptoAlgorithmsRegistry.prototype.registerEncryptionKeyGenerationFunction = (keySSIType, vn, keyGeneratorFunction) => {
    registerCryptoFunction(keySSIType, vn, 'encryptionKeyGeneration', keyGeneratorFunction);
};

CryptoAlgorithmsRegistry.prototype.getEncryptionKeyGenerationFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'encryptionKeyGeneration');
};

CryptoAlgorithmsRegistry.prototype.registerDecryptionFunction = (keySSIType, vn, decryptionFunction) => {
    registerCryptoFunction(keySSIType, vn, 'decryption', decryptionFunction);
};

CryptoAlgorithmsRegistry.prototype.getDecryptionFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'decryption');
};

CryptoAlgorithmsRegistry.prototype.registerEncodingFunction = (keySSIType, vn, encodingFunction) => {
    registerCryptoFunction(keySSIType, vn, 'encoding', encodingFunction);
};

CryptoAlgorithmsRegistry.prototype.getEncodingFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'encoding');
};

CryptoAlgorithmsRegistry.prototype.registerDecodingFunction = (keySSIType, vn, decodingFunction) => {
    registerCryptoFunction(keySSIType, vn, 'decoding', decodingFunction);
};

CryptoAlgorithmsRegistry.prototype.getDecodingFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'decoding');
};

CryptoAlgorithmsRegistry.prototype.registerKeyPairGenerator = (keySSIType, vn, keyPairGenerator) => {
    registerCryptoFunction(keySSIType, vn, 'keyPairGenerator', keyPairGenerator);
};

CryptoAlgorithmsRegistry.prototype.getKeyPairGenerator = (keySSI) => {
    return getCryptoFunction(keySSI, 'keyPairGenerator');
};

CryptoAlgorithmsRegistry.prototype.registerSignFunction = (keySSIType, vn, signFunction) => {
    registerCryptoFunction(keySSIType, vn, 'sign', signFunction);
};


CryptoAlgorithmsRegistry.prototype.getSignFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'sign');
};

CryptoAlgorithmsRegistry.prototype.registerVerifyFunction = (keySSIType, vn, verifyFunction) => {
    registerCryptoFunction(keySSIType, vn, 'verify', verifyFunction);
};

CryptoAlgorithmsRegistry.prototype.getVerifyFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'verify');
};

CryptoAlgorithmsRegistry.prototype.registerDerivePublicKeyFunction = (keySSIType, vn, deriveFunction) => {
    registerCryptoFunction(keySSIType, vn, 'derivePublicKey', deriveFunction);
};

CryptoAlgorithmsRegistry.prototype.getDerivePublicKeyFunction = (keySSI) => {
    return getCryptoFunction(keySSI, 'derivePublicKey');
};

module.exports = new CryptoAlgorithmsRegistry();



/* Initialisation */


let defaultKeySSISign = (data, privateKey) => {
    const keyGenerator = crypto.createKeyPairGenerator();
    const rawPublicKey = keyGenerator.getPublicKey(privateKey, 'secp256k1');
    return crypto.sign('sha256', data, keyGenerator.getPemKeys(privateKey, rawPublicKey).privateKey);
}

let defaultKeySSIVerify = (data, publicKey, signature) => {
    return crypto.verify('sha256', data, publicKey, signature);
}

let defaultKeySSIDerivePublicKey =  (privateKey, format) => {
    if (typeof format === "undefined") {
        format = "pem";
    }
    const keyGenerator = crypto.createKeyPairGenerator();
    let publicKey = keyGenerator.getPublicKey(privateKey, 'secp256k1');
    switch(format){
        case "raw":
            return publicKey;
        case "pem":
            return keyGenerator.getPemKeys(privateKey, publicKey).publicKey;
        default:
            throw Error("Invalid format name");
    }
}


CryptoAlgorithmsRegistry.prototype.registerSignFunction(SSITypes.SEED_SSI, "v0", defaultKeySSISign);
CryptoAlgorithmsRegistry.prototype.registerVerifyFunction(SSITypes.SEED_SSI, "v0", defaultKeySSIVerify);
CryptoAlgorithmsRegistry.prototype.registerDerivePublicKeyFunction(SSITypes.SEED_SSI, "v0", defaultKeySSIDerivePublicKey);
CryptoAlgorithmsRegistry.prototype.registerVerifyFunction(SSITypes.SREAD_SSI, "v0", defaultKeySSIVerify);


CryptoAlgorithmsRegistry.prototype.registerSignFunction(SSITypes.ROOT_SSI, "v0", defaultKeySSISign);
CryptoAlgorithmsRegistry.prototype.registerSignFunction(SSITypes.NODE_SSI, "v0", defaultKeySSISign);
CryptoAlgorithmsRegistry.prototype.registerVerifyFunction(SSITypes.LEAF_SSI, "v0", defaultKeySSIVerify);
