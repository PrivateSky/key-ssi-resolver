const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");

function TransferSSI(identifier) {
    KeySSIMixin(this);
    const self = this;
    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = function (dlDomain, hashNewPublicKey, timestamp, signature, vn, hint, callback) {
        if (typeof vn === "function") {
            callback = vn;
            vn = "v0";
        }
        if (typeof hint === "function") {
            callback = hint;
            hint = undefined;
        }

        self.load(SSITypes.TRANSFER_SSI, dlDomain, hashNewPublicKey, `${timestamp}/${signature.signature}/${signature.publicKey}`, vn, hint);

        if (callback) {
            callback(undefined, self);
        }

        self.initialize = function () {
            throw Error("KeySSI already initialized");
        };
    };

    self.getPublicKeyHash = function () {
        return self.getSpecificString();
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
}

function createTransferSSI(identifier) {
    return new TransferSSI(identifier);
}

module.exports = {
    createTransferSSI
};
