const KeySSIMixin = require("../KeySSIMixin");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../../CryptoAlgorithms/CryptoAlgorithmsRegistry");

function SymmetricalEncryptionSSI(identifier) {
    KeySSIMixin(this);
    const self = this;
    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.getTypeName = () => {
        return SSITypes.SYMMETRICAL_ENCRYPTION_SSI;
    };

    let load = self.load;
    self.load = function (subtype, dlDomain, encryptionKey, control, vn, hint){
        if (typeof encryptionKey === "undefined") {
            encryptionKey = cryptoRegistry.getEncryptionKeyGenerationFunction(self)();
        }

        if ($$.Buffer.isBuffer(encryptionKey)) {
            encryptionKey = cryptoRegistry.getEncodingFunction(self)(encryptionKey);
        }

        load(subtype, dlDomain, encryptionKey, '', vn, hint);
    }

    self.getEncryptionKey = function() {
        return cryptoRegistry.getDecodingFunction(self)(self.getSpecificString());
    };

    self.derive = function (){
        throw Error("Not implemented");
    }
}

function createSymmetricalEncryptionSSI(identifier) {
    return new SymmetricalEncryptionSSI(identifier);
}

module.exports = {
    createSymmetricalEncryptionSSI
};
