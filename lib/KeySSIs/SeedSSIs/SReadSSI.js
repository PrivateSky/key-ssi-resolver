const KeySSIMixin = require("../KeySSIMixin");
const SZaSSI = require("./SZaSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

function SReadSSI(enclave, identifier) {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }
    KeySSIMixin(this, enclave);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = function () {
        return SSITypes.SREAD_SSI;
    }

    self.initialize = (dlDomain, vn, hint) => {
        self.load(SSITypes.SREAD_SSI, dlDomain, "", undefined, vn, hint);
    };

    self.derive = (callback) => {
        const sZaSSI = SZaSSI.createSZaSSI();
        const subtypeKey = '';
        const subtypeControl = self.getControlString();
        sZaSSI.load(SSITypes.SZERO_ACCESS_SSI, self.getDLDomain(), subtypeKey, subtypeControl, self.getVn(), self.getHint());
        callback(undefined, sZaSSI);
    };

    self.getEncryptionKey = (callback) => {
        const encryptionKey = cryptoRegistry.getDecodingFunction(self)(self.getSpecificString());
        callback(undefined, encryptionKey);
    };

    self.getPublicKey = (options) => {
        let publicKey = cryptoRegistry.getBase64DecodingFunction(self)(self.getControlString());
        return cryptoRegistry.getConvertPublicKeyFunction(self)(publicKey, options);
    };
}

function createSReadSSI(enclave, identifier) {
    return new SReadSSI(enclave, identifier)
}

module.exports = {
    createSReadSSI
};
