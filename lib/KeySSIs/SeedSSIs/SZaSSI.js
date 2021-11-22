const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");

function SZaSSI(enclave, identifier) {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }
    const self = this;
    KeySSIMixin(self, enclave);

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = function () {
        return SSITypes.SZERO_ACCESS_SSI;
    }

    self.initialize = (dlDomain, hpk, vn, hint) => {
        self.load(SSITypes.SZERO_ACCESS_SSI, dlDomain, '', hpk, vn, hint);
    };

    self.derive = () => {
        throw Error("Not implemented");
    };
}

function createSZaSSI(enclave, identifier) {
    return new SZaSSI(enclave, identifier);
}

module.exports = {
    createSZaSSI
};
