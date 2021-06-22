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

    self.initialize = (compatibleFamilyName, publicKey, vn) => {
        publicKey = cryptoRegistry.getEncodingFunction(self)(publicKey);
        self.load(SSITypes.PUBLIC_KEY_SSI, '', compatibleFamilyName, publicKey, vn);
    };

    self.getPublicKey = (format) => {
        let publicKey = cryptoRegistry.getDecodingFunction(self)(self.getControlString());
        if (format !== "raw") {
            publicKey = cryptoRegistry.getConvertPublicKeyFunction(self)(publicKey, {outputFormat: format});
        }

        return publicKey;
    };

    self.generateCompatiblePowerfulKeySSI = (callback) => {
        const keySSIFactory = require("../KeySSIFactory");
        const powerfulSSI = keySSIFactory.createType(self.getSpecificString());
        powerfulSSI.initialize(self.getDLDomain(), undefined, undefined, self.getVn(), callback);
    }
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
