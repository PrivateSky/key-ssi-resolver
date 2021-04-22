const KeySSIMixin = require("../KeySSIMixin");
const ConstSSI = require("./ConstSSI");
const SSITypes = require("../SSITypes");
const cryptoRegistry = require("../CryptoAlgorithmsRegistry");

function PasswordSSI(identifier){
    KeySSIMixin(this);
    const self = this;

    if (typeof identifier !== "undefined") {
        self.autoLoad(identifier);
    }

    self.initialize = (dlDomain, context, password, kdfOptions, vn, hint) => {
        const subtypeSpecificString = cryptoRegistry.getKeyDerivationFunction(self)(context + password, kdfOptions);
        self.load(SSITypes.PASSWORD_SSI, dlDomain, subtypeSpecificString, '', vn, hint);
    };

    self.derive = () => {
        const constSSI = ConstSSI.createConstSSI();
        constSSI.load(SSITypes.CONST_SSI, self.getDLDomain(), self.getSubtypeSpecificString(), self.getControlString(), self.getVn(), self.getHint());
        return constSSI;
    };

    self.getEncryptionKey = () => {
        return self.derive().getEncryptionKey();
    };
}

function createPasswordSSI(identifier) {
    return new PasswordSSI(identifier);
}

module.exports = {
    createPasswordSSI
};