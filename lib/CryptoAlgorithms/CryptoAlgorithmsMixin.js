function CryptoAlgorithmsMixin(target) {
    target = target || {};
    const crypto = require("pskcrypto");

    target.hash = (data) => {
        return target.encoding(crypto.hash('sha256', data));
    }

    target.keyDerivation = (password, iterations) => {
        return crypto.deriveKey('aes-256-gcm', password, iterations);
    }

    target.encryptionKeyGeneration = () => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        return pskEncryption.generateEncryptionKey();
    }

    target.encryption = (plainData, encryptionKey, options) => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        return pskEncryption.encrypt(plainData, encryptionKey, options);
    }

    target.decryption = (encryptedData, decryptionKey, authTagLength, options) => {
        const pskEncryption = crypto.createPskEncryption('aes-256-gcm');
        const utils = require("swarmutils");
        if (!$$.Buffer.isBuffer(decryptionKey) && (decryptionKey instanceof ArrayBuffer || ArrayBuffer.isView(decryptionKey))) {
            decryptionKey = utils.ensureIsBuffer(decryptionKey);
        }
        if (!$$.Buffer.isBuffer(encryptedData) && (decryptionKey instanceof ArrayBuffer || ArrayBuffer.isView(decryptionKey))) {
            encryptedData = utils.ensureIsBuffer(encryptedData);
        }
        return pskEncryption.decrypt(encryptedData, decryptionKey, 16, options);
    }

    target.encoding = (data) => {
        return crypto.pskBase58Encode(data);
    }

    target.decoding = (data) => {
        return crypto.pskBase58Decode(data);
    }

    target.keyPairGenerator = () => {
        return crypto.createKeyPairGenerator();
    }


    target.convertPublicKeyToPem = (rawPublicKey) => {
        const keyGenerator = crypto.createKeyPairGenerator();
        return keyGenerator.convertPublicKey(rawPublicKey);
    };

    target.verify = (data, publicKey, signature) => {
        return crypto.verify('sha256', data, publicKey, signature);
    }

    return target;
}

module.exports = CryptoAlgorithmsMixin;
