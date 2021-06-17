const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

function PublicKeySSI(identifier) {
    KeySSIMixin(this);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = function () {
        return SSITypes.PUBLIC_KEY_SSI;
    }

    self.initialize = (dlDomain, publicKey, vn, hint) => {
        publicKey = cryptoRegistry.getEncodingFunction(self)(publicKey);
        self.load(SSITypes.PUBLIC_KEY_SSI, dlDomain, publicKey, '', vn, hint);
    };

    self.getPublicKey = (format) => {
        let publicKey = cryptoRegistry.getDecodingFunction(self)(self.getSpecificString());
        if (format !== "raw") {
            publicKey = cryptoRegistry.getConvertPublicKeyFunction(self)(publicKey, {outputFormat: format});
        }

        return publicKey;
    };

    self.derive = () => {
        throw Error("Not implemented");
    };
}

function createPublicKeySSI(identifier) {
    return new PublicKeySSI(identifier);
}

module.exports = {
    createPublicKeySSI
};
