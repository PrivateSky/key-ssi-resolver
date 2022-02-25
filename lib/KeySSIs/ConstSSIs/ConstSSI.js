const KeySSIMixin = require("../KeySSIMixin");
const CZaSSI = require("./CZaSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");
const keySSIFactory = require("../KeySSIFactory");

function ConstSSI(enclave, identifier) {
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
        return SSITypes.CONST_SSI;
    }

    self.initialize = (dlDomain, constString, vn, hint) => {
        const key = cryptoRegistry.getKeyDerivationFunction(self)(constString, 1000);
        self.load(SSITypes.CONST_SSI, dlDomain, cryptoRegistry.getBase64EncodingFunction(self)(key), "", vn, hint);
    };

    self.getEncryptionKey = () => {
        return cryptoRegistry.getBase64DecodingFunction(self)(self.getSpecificString());
    };

    self.derive = () => {
        const cZaSSI = CZaSSI.createCZaSSI();
        const subtypeKey = cryptoRegistry.getHashFunction(self)(self.getEncryptionKey());
        cZaSSI.load(SSITypes.CONSTANT_ZERO_ACCESS_SSI, self.getDLDomain(), subtypeKey, self.getControlString(), self.getVn(), self.getHint());
        return cZaSSI;
    };

    self.createAnchorValue = function (brickMapHash) {
        const keySSIFactory = require("../KeySSIFactory");
        const hashLinkSSI = keySSIFactory.createType(SSITypes.HASH_LINK_SSI);
        hashLinkSSI.initialize(self.getBricksDomain(), brickMapHash, self.getVn(), self.getHint());
        return hashLinkSSI;
    }
}

function createConstSSI(enclave, identifier) {
    return new ConstSSI(enclave, identifier);
}

module.exports = {
    createConstSSI
};
