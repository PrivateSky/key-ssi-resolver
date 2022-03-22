function ArraySSI(enclave, identifier) {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }
    const SSITypes = require("../SSITypes");
    const KeySSIMixin = require("../KeySSIMixin");
    const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

    KeySSIMixin(this, enclave);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = function () {
        return SSITypes.ARRAY_SSI;
    }

    self.initialize = (dlDomain, arr, vn, hint) => {
        if (typeof vn === "undefined") {
            vn = 'v0';
        }
        const key = cryptoRegistry.getKeyDerivationFunction(self)(arr.join(''), 1000);
        self.load(SSITypes.ARRAY_SSI, dlDomain, cryptoRegistry.getBase64EncodingFunction(self)(key), "", vn, hint);
    };

    self.derive = () => {
        const ConstSSI = require("./ConstSSI");
        const constSSI = ConstSSI.createConstSSI();
        constSSI.load(SSITypes.CONST_SSI, self.getDLDomain(), self.getSpecificString(), self.getControlString(), self.getVn(), self.getHint());
        return constSSI;
    };

    self.getEncryptionKey = () => {
        return self.derive().getEncryptionKey();
    };

    self.createAnchorValue = function (brickMapHash, previousAnchorValue, callback) {
        if (typeof previousAnchorValue === "function") {
            callback = previousAnchorValue;
            previousAnchorValue = undefined;
        }
        const keySSIFactory = require("../KeySSIFactory");
        const hashLinkSSI = keySSIFactory.createType(SSITypes.HASH_LINK_SSI);
        hashLinkSSI.initialize(self.getBricksDomain(), brickMapHash, self.getVn(), self.getHint());
        callback(undefined, hashLinkSSI);
    }
}

function createArraySSI(enclave, identifier) {
    return new ArraySSI(enclave, identifier);
}

module.exports = {
    createArraySSI
};
