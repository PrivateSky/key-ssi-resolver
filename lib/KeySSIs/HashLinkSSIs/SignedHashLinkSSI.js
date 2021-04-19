const KeySSIMixin = require("../KeySSIMixin");
const { createHashLinkSSI } = require("../OtherKeySSIs/HashLinkSSI");
const SSITypes = require("../SSITypes");

function SignedHashLinkSSI(identifier) {
    KeySSIMixin(this);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = (dlDomain, hashLink, timestamp, signature, vn, hint) => {
        self.load(SSITypes.SIGNED_HASH_LINK_SSI, dlDomain, hashLink, `${timestamp}/${JSON.stringify(signature)}`, vn, hint);
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
        hashLinkSSI.autoLoad(self.getHash());
        // hashLinkSSI.load(SSITypes.HASH_LINK_SSI, self.getDLDomain(), self.getHash(), "", self.getVn(), self.getHint());
        return hashLinkSSI;
    };

    self.getTimestamp = function (){
        let control = self.getControl;
        return control.split("/")[0];
    }

    self.getSignature = function (){
        let control = self.getControl;
        let splitControl = control.split("/");
        let signature = splitControl[1];
        if (splitControl.length > 2) {
            signature = splitControl.slice(1).join("/");
        }

        return JSON.parse(signature);
    }
}

function createSignedHashLinkSSI(identifier) {
    return new SignedHashLinkSSI(identifier);
}

module.exports = {
    createSignedHashLinkSSI
};
