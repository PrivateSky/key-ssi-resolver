const KeySSIMixin = require("../KeySSIMixin");
const { createHashLinkSSI } = require("../OtherKeySSIs/HashLinkSSI");
const SSITypes = require("../SSITypes");

function SignedHashLinkSSI(identifier) {
    KeySSIMixin(this);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = (dlDomain, hashLink, timestampAndSignature, vn, hint) => {
        self.load(SSITypes.SIGNED_HASH_LINK_SSI, dlDomain, hashLink, timestampAndSignature, vn, hint);
    };

    self.getHash = () => {
        const specificString = self.getSpecificString();
        if (typeof specificString !== "string") {
            console.trace("Specific string is not string", specificString.toString());
        }
        return specificString;
    };

    self.derive = () => {
        const hashLinkSSI = createHashLinkSSI();
        hashLinkSSI.load(SSITypes.HASH_LINK_SSI, self.getDLDomain(), self.getHash(), "", self.getVn(), self.getHint());
        return hashLinkSSI;
    };
}

function createSignedHashLinkSSI(identifier) {
    return new SignedHashLinkSSI(identifier);
}

module.exports = {
    createSignedHashLinkSSI,
};
