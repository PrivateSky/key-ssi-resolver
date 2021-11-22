const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");

function HashLinkSSI(enclave, identifier) {
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
        return SSITypes.HASH_LINK_SSI;
    }

    self.initialize = (dlDomain, hash, vn, hint) => {
        self.load(SSITypes.HASH_LINK_SSI, dlDomain, hash, '', vn, hint);
    };

    self.getHash = () => {
        const specificString = self.getSpecificString();
        if (typeof specificString !== "string") {
            console.trace("Specific string is not string", specificString.toString());
        }
        return specificString;
    };

    self.derive = () => {
        throw Error("Not implemented");
    };
}

function createHashLinkSSI(enclave, identifier) {
    return new HashLinkSSI(enclave, identifier);
}

module.exports = {
    createHashLinkSSI
};
