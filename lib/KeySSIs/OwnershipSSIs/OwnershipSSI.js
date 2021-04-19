const KeySSIMixin = require("../KeySSIMixin");
const OReadSSI = require("./OReadSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../CryptoAlgorithmsRegistry");

function OwnershipSSI(identifier) {
    KeySSIMixin(this);
    const self = this;
    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.setCanSign(true);

    self.initialize = function (dlDomain, privateKey, levelAndToken, vn, hint, callback) {
        if (typeof privateKey === "function") {
            callback = privateKey;
            privateKey = undefined;
        }
        if (typeof levelAndToken === "function") {
            callback = levelAndToken;
            levelAndToken = undefined;
        }
        if (typeof vn === "function") {
            callback = vn;
            vn = "v0";
        }
        if (typeof hint === "function") {
            callback = hint;
            hint = undefined;
        }

        if (typeof privateKey === "undefined") {
            cryptoRegistry
                .getKeyPairGenerator(self)()
                .generateKeyPair((err, publicKey, privateKey) => {
                    if (err) {
                        return OpenDSUSafeCallback(callback)(
                            createOpenDSUErrorWrapper(`Failed generate private/public key pair`, err)
                        );
                    }
                    privateKey = cryptoRegistry.getEncodingFunction(self)(privateKey);
                    self.load(SSITypes.OWNERSHIP_SSI, dlDomain, privateKey, levelAndToken, vn, hint);
                    if (callback) {
                        callback(undefined, self);
                    }
                });
        } else {
            self.load(SSITypes.OWNERSHIP_SSI, dlDomain, privateKey, levelAndToken, vn, hint);
            if (callback) {
                callback(undefined, self);
            }
        }
        self.initialize = function () {
            throw Error("KeySSI already initialized");
        };
    };

    self.derive = function () {
        const oReadSSI = OReadSSI.createOReadSSI();
        const privateKey = self.getPrivateKey();
        const publicKey = cryptoRegistry.getDerivePublicKeyFunction(self)(privateKey, "raw");
        const publicKeyHash = cryptoRegistry.getHashFunction(self)(publicKey);
        const levelAndToken = self.getControl();

        const oReadSpecificString = cryptoRegistry.getHashFunction(self)(privateKey);
        const oReadControl = `${publicKeyHash}/${levelAndToken}`;
        oReadSSI.load(
            SSITypes.OWNERSHIP_READ_SSI,
            self.getDLDomain(),
            oReadSpecificString,
            oReadControl,
            self.getVn(),
            self.getHint()
        );
        return oReadSSI;
    };

    self.getPrivateKey = function (format) {
        let validSpecificString = self.getSpecificString();
        if (validSpecificString === undefined) {
            throw Error("Operation requested on an invalid OwnershipSSI. Initialise first");
        }
        let privateKey = cryptoRegistry.getDecodingFunction(self)(validSpecificString);
        if (format === "pem") {
            const pemKeys = cryptoRegistry.getKeyPairGenerator(self)().getPemKeys(privateKey, self.getPublicKey("raw"));
            privateKey = pemKeys.privateKey;
        }
        return privateKey;
    };

    self.sign = function (dataToSign){
        const privateKey = self.getPrivateKey();
        const sign = cryptoRegistry.getSignFunction(self);
        const encode = cryptoRegistry.getEncodingFunction(self);
        const digitalProof = {};
        digitalProof.signature = encode(sign(dataToSign, privateKey));
        digitalProof.publicKey = encode(self.getPublicKey("raw"));

        return digitalProof;
    }


    self.getPrivateKeyHash = function () {       
        return cryptoRegistry.getHashFunction(self)(self.getPrivateKey());
    };

    self.getPublicKey = function (format) {
        return cryptoRegistry.getDerivePublicKeyFunction(self)(self.getPrivateKey(), format);
    };

    self.getPublicKeyHash = function () {
        const publicKey = cryptoRegistry.getDerivePublicKeyFunction(self)(self.getPrivateKey(), "raw");
        const publicKeyHash = cryptoRegistry.getHashFunction(self)(publicKey);
        return publicKeyHash;
    };

    self.getEncryptionKey = function () {
        return self.derive().getEncryptionKey();
    };

    const getControlParts = function () {
        let control = self.getControl();
        if (control == null) {
            throw Error("Operation requested on an invalid OwnershipSSI. Initialise first");
        }
        return control.split("/");
    };

    self.getLevel = function () {
        let level = getControlParts()[0];
        return level;
    };

    self.getToken = function () {
        let token = getControlParts()[1];
        return token;
    };
}

function createOwnershipSSI(identifier) {
    return new OwnershipSSI(identifier);
}

module.exports = {
    createOwnershipSSI
};
