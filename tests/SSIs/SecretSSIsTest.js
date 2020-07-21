require("../../../../psknode/bundles/testsRuntime");
const assert = require("double-check").assert;
const SSITypes = require("../../lib/KeySSIs/SSITypes");

const KeySSIFactory = require("../../lib/KeySSIs/KeySSIFactory");

const secretSSI = KeySSIFactory.createKeySSI(SSITypes.SECRET_SSI);
secretSSI.load(SSITypes.SECRET_SSI, "domain", "subtype specific string", "v0");

assert.callback("KeySSIs test", (callback) => {
    KeySSIFactory.getRelatedType(secretSSI, SSITypes.PUBLIC_SSI, (err, publicSSI) => {
        if (err) {
            throw err;
        }
        assert.true(publicSSI.getName() === SSITypes.PUBLIC_SSI);
        callback();
    });
}, 2000);