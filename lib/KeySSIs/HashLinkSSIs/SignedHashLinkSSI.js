const KeySSIMixin = require("../KeySSIMixin");
const { createHashLinkSSI } = require("../OtherKeySSIs/HashLinkSSI");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");
const SSITypes = require("../SSITypes");

function SignedHashLinkSSI(enclave, identifier) {
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
        return SSITypes.SIGNED_HASH_LINK_SSI;
    }

    self.initialize = (dlDomain, hashLink, timestamp, signature, vn, hint) => {
        self.load(SSITypes.SIGNED_HASH_LINK_SSI, dlDomain, hashLink, `${timestamp}/${signature.signature}`, vn, hint);
    };

    self.canBeVerified = () => {
        return true;
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

    self.getTimestamp = function (){
        let control = self.getControlString();
        return control.split("/")[0];
    }

    self.getSignature = function (){
        let control = self.getControlString();
        let splitControl = control.split("/");
        let signature = splitControl[1];
        return signature;
    }
}

function createSignedHashLinkSSI(enclave, identifier) {
    return new SignedHashLinkSSI(enclave, identifier);
}

module.exports = {
    createSignedHashLinkSSI
};
