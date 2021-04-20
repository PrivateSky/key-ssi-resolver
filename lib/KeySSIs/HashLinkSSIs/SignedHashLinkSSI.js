const KeySSIMixin = require("../KeySSIMixin");
const { createHashLinkSSI } = require("../OtherKeySSIs/HashLinkSSI");
const cryptoRegistry = require("../CryptoAlgorithmsRegistry");
const SSITypes = require("../SSITypes");

function SignedHashLinkSSI(identifier) {
    KeySSIMixin(this);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = (dlDomain, hashLink, timestamp, signature, vn, hint) => {
        self.load(SSITypes.SIGNED_HASH_LINK_SSI, dlDomain, hashLink, `${timestamp}/${signature.signature}/${signature.publicKey}`, vn, hint);
    };

    self.getHashLink = () => {
        const specificString = self.getSpecificString();
        if (typeof specificString !== "string") {
            console.trace("Specific string is not string", specificString.toString());
        }
        return specificString;
    };

    self.getHash = () => {
        return self.derive().getHash();
    };

    self.derive = () => {
        const hashLinkSSI = createHashLinkSSI();
        hashLinkSSI.autoLoad(self.getHashLink());
        // hashLinkSSI.load(SSITypes.HASH_LINK_SSI, self.getDLDomain(), self.getHash(), "", self.getVn(), self.getHint());
        return hashLinkSSI;
    };

    self.getTimestamp = function (){
        let control = self.getControl();
        return control.split("/")[0];
    }

    self.getSignature = function (){
        let control = self.getControl();
        let splitControl = control.split("/");
        let signature = splitControl[1];
        let publicKey = splitControl[2];
        return {signature, publicKey};
    }

    self.getPublicKeyHash = function () {
        const {publicKey} = self.getSignature();
        const decodedPublicKey = cryptoRegistry.getDecodingFunction(self)(publicKey);
        return cryptoRegistry.getHashFunction(self)(decodedPublicKey);
    };
}

function createSignedHashLinkSSI(identifier) {
    return new SignedHashLinkSSI(identifier);
}

module.exports = {
    createSignedHashLinkSSI
};
