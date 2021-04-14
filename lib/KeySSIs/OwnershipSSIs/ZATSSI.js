const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");

function ZATSSI(identifier) {
    const self = this;
    KeySSIMixin(self);

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = (dlDomain, token, hashInitialOwnerPublicKey, vn, hint) => {
        self.load(SSITypes.ZERO_ACCESS_TOKEN_SSI, dlDomain, token, hashInitialOwnerPublicKey, vn, hint);
    };

    self.derive = () => {
        throw Error("Not implemented");
    };
}

function createZATSSI(identifier) {
    return new ZATSSI(identifier);
}

module.exports = {
    createZATSSI
};