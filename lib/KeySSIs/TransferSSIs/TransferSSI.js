const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");

function TransferSSI(enclave, identifier) {
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
        return SSITypes.TRANSFER_SSI;
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
        let control = self.getControlString();
        return control.split("/")[0];
    }

    self.getSignature = function (){
        let control = self.getControlString();
        let splitControl = control.split("/");
        let signature = splitControl[1];
        let publicKey = splitControl[2];
        return {signature, publicKey};
    }
}

function createTransferSSI(enclave, identifier) {
    return new TransferSSI(enclave, identifier);
}

module.exports = {
    createTransferSSI
};
