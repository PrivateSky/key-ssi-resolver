const KeySSIMixin = require("../KeySSIMixin");
const SZaSSI = require("./SZaSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

function SReadSSI(identifier) {
    KeySSIMixin(this);
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

    self.derive = () => {
        const sZaSSI = SZaSSI.createSZaSSI();
        const subtypeKey = '';
        const subtypeControl = self.getControlString();
        sZaSSI.load(SSITypes.SZERO_ACCESS_SSI, self.getDLDomain(), subtypeKey, subtypeControl, self.getVn(), self.getHint());
        return sZaSSI;
    };

    self.getEncryptionKey = () => {
        return cryptoRegistry.getDecodingFunction(self)(self.getControlString());
    };
}

function createSReadSSI(identifier) {
    return new SReadSSI(identifier)
}

module.exports = {
    createSReadSSI
};
