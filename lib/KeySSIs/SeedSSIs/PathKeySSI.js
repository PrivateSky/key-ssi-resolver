const KeySSIMixin = require("../KeySSIMixin");
const SeedSSI = require("./SeedSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

function PathKeySSI(enclave, identifier) {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }
    KeySSIMixin(this, enclave);
    const self = this;
    let privateKey;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = function () {
        return SSITypes.PATH_SSI;
    }

    self.setCanSign(true);

    self.derive = function (callback) {
        const splitSpecificString = self.getSpecificString().split("/");
        const slot = splitSpecificString[0];
        const path = splitSpecificString[1];

        const __getPrivateKeyForSlot = () => {
            enclave.getPrivateKeyForSlot(slot, (err, _privateKey)=>{
                if (err) {
                    return callback(err);
                }

                privateKey = _privateKey;
                privateKey = cryptoRegistry.getHashFunction(self)(`${path}${privateKey}`);
                privateKey = cryptoRegistry.getDecodingFunction(self)(privateKey);
                const seedSpecificString = cryptoRegistry.getBase64EncodingFunction(self)(privateKey);
                const seedSSI = SeedSSI.createSeedSSI(enclave);
                seedSSI.load(SSITypes.SEED_SSI, self.getDLDomain(), seedSpecificString, undefined, self.getVn(), self.getHint());
                callback(undefined, seedSSI);
            });
        }

        if (typeof enclave === "undefined") {
            require("opendsu").loadAPI("sc").getMainEnclave((err, mainEnclave)=>{
                if (err) {
                    return callback(err);
                }

                enclave = mainEnclave;
                __getPrivateKeyForSlot();
            })

            return;
        }

        __getPrivateKeyForSlot();
    };

    self.getPrivateKey = function (format) {
        let validSpecificString = self.getSpecificString();
        if (validSpecificString === undefined) {
            throw Error("Operation requested on an invalid SeedSSI. Initialise first")
        }
        let privateKey = cryptoRegistry.getBase64DecodingFunction(self)(validSpecificString);
        if (format === "pem") {
            const pemKeys = cryptoRegistry.getKeyPairGenerator(self)().getPemKeys(privateKey, self.getPublicKey("raw"));
            privateKey = pemKeys.privateKey;
        }
        return privateKey;
    }

    self.sign = function (dataToSign, callback) {
        self.derive((err, seedSSI)=>{
            if (err) {
                return callback(err);
            }

            seedSSI.sign(dataToSign, callback);
        })
    }

    self.getPublicKey = function (format) {
        return cryptoRegistry.getDerivePublicKeyFunction(self)(self.getPrivateKey(), format);
    }

    self.getEncryptionKey = function (callback) {
        self.derive((err, seedSSI)=>{
            if (err) {
                return callback(err);
            }

            seedSSI.getEncryptionKey(callback);
        })
    };

    self.getKeyPair = function () {
        const keyPair = {
            privateKey: self.getPrivateKey("pem"),
            publicKey: self.getPublicKey("pem")
        }

        return keyPair;
    }
}

function createPathKeySSI(enclave, identifier) {
    return new PathKeySSI(enclave, identifier);
}

module.exports = {
    createPathKeySSI
};
