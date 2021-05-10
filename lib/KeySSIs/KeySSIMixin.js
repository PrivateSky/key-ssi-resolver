const cryptoRegistry = require("../CryptoAlgorithms/CryptoAlgorithmsRegistry");
const {BRICKS_DOMAIN_KEY} = require('opendsu').constants
const pskCrypto = require("pskcrypto");

const MAX_KEYSSI_LENGTH = 2048

function keySSIMixin(target) {
    let _prefix = "ssi";
    let _subtype;
    let _dlDomain;
    let _subtypeSpecificString;
    let _controlString;
    let _vn = "v0";
    let _hint;
    let _hintObject = {};
    let _dsa = false;
    let _securityContext = false;

    const _createHintObject = (hint = _hint) => {
        try {
            _hintObject = JSON.parse(hint)
        } catch (error) {
            //console.error('Parsing of hint failed, hint:', hint)
            _hintObject = {
                value: hint
            }
        }
    }

    const _inferJSON = (hintString) => {
        return hintString[0] === '{' || hintString[0] === '['
    }

    target.autoLoad = function (identifier) {
        if (typeof identifier === "undefined") {
            return;
        }

        if (typeof identifier !== "string") {
            throw new Error("The identifier should be string");
        }

        target.validateKeySSICharLength();

        let originalId = identifier;
        if (identifier.indexOf(":") === -1) {
            identifier = pskCrypto.pskBase58Decode(identifier).toString();
        }

        if (identifier.indexOf(":") === -1) {
            throw new Error(`Wrong format of SSI. ${originalId} ${identifier}`);
        }

        let segments = identifier.split(":");
        segments.shift();
        _subtype = segments.shift();
        _dlDomain = segments.shift();
        _subtypeSpecificString = segments.shift();
        _controlString = segments.shift();
        let version = segments.shift();
        if (version !== '') {
            _vn = version;
        }
        if (segments.length > 0) {
            _hint = segments.join(":");
            if (_inferJSON(_hint)) {
                _createHintObject(_hint);
            }
        }
        // _subtypeSpecificString = cryptoRegistry.getDecodingFunction(target)(_subtypeSpecificString);
    }

    target.validateKeySSICharLength = () => {
        if (target.getIdentifier() > MAX_KEYSSI_LENGTH) {
            throw new Error(`The identifier length exceed maximum char length ${MAX_KEYSSI_LENGTH}`);
        }
    }

    target.load = function (subtype, dlDomain, subtypeSpecificString, control, vn, hint) {
        _subtype = subtype;
        _dlDomain = dlDomain;
        _subtypeSpecificString = subtypeSpecificString;
        _controlString = control;
        _vn = vn || "v0";
        _hint = hint;

        target.validateKeySSICharLength();

        if (_hint) {
            _createHintObject(_hint)
        }
    }

    /**
     *
     * @param ssiType - string
     * @param callback - function
     */
    target.getRelatedType = function (ssiType, callback) {
        const KeySSIFactory = require("./KeySSIFactory");
        KeySSIFactory.getRelatedType(target, ssiType, callback);
    }

    target.getRootKeySSITypeName = function () {
        const KeySSIFactory = require("./KeySSIFactory");
        return KeySSIFactory.getRootKeySSITypeName(target);
    }

    target.getAnchorId = function () {
        const keySSIFactory = require("./KeySSIFactory");
        return keySSIFactory.getAnchorType(target).getNoHintIdentifier();
    }

    target.getSpecificString = function () {
        return _subtypeSpecificString;
    }

    target.getName = function () {
        console.trace("Obsolete function. Replace with getTypeName");
        return _subtype;
    }

    target.getTypeName = function () {
        return _subtype;
    }

    target.getDLDomain = function () {
        return _dlDomain;
    }

    target.getControlString = function () {
        return _controlString;
    }

    target.getHint = function () {
        return _hint;
    }

    target.getVn = function () {
        return _vn;
    }

    target.getDSURepresentationName = function () {
        const DSURepresentationNames = require("./DSURepresentationNames");
        return DSURepresentationNames[_subtype];
    }

    target.getNoHintIdentifier = function (plain) {
        let identifier = `${_prefix}:${target.getTypeName()}:${_dlDomain}:${_subtypeSpecificString}:${_controlString}:${_vn}`;
        return plain ? identifier : pskCrypto.pskBase58Encode(identifier);
    }

    target.getIdentifier = function (plain) {
        let id = target.getNoHintIdentifier(true);

        if (typeof _hint !== "undefined") {
            id += ":" + _hint;
        }

        return plain ? id : pskCrypto.pskBase58Encode(id);
    }

    target.getBricksDomain = function () {
        return _hintObject[BRICKS_DOMAIN_KEY] ? _hintObject[BRICKS_DOMAIN_KEY] : _dlDomain;
    }

    target.clone = function () {
        let clone = {};
        clone.prototype = target.prototype;
        for (let attr in target) {
            if (target.hasOwnProperty(attr)) {
                clone[attr] = target[attr];
            }
        }
        keySSIMixin(clone);
        return clone;
    }

    target.cast = function (newType) {
        target.getTypeName = () => {
            return newType;
        };
        target.load(newType, _dlDomain, _subtypeSpecificString, _controlString, _vn, _hint);
    }

    target.canSign = () => {
        return _dsa
    }

    target.setCanSign = (dsa) => {
        _dsa = dsa
    }

    target.canBeVerified = () => {
        return false;
    };

    target.sign = (dataToSign, callback) => {
        const sc = require("opendsu").loadAPI("sc").getSecurityContext();
        sc.sign(target, dataToSign, callback);
    };

    target.verify = (data, digitalProof) => {
        if (typeof digitalProof === "string") {
            try{
                digitalProof = JSON.parse(digitalProof);
            }catch (e) {
                throw createOpenDSUErrorWrapper("Failed to parse string signature", e);
            }
        }
        const convertPublicKey = cryptoRegistry.getConvertPublicKeyToPemFunction(target);
        const decode = cryptoRegistry.getDecodingFunction(target);
        const decodedPublicKey = decode(digitalProof.publicKey);

        // const hash = cryptoRegistry.getHashFunction(target);
        // const hpk = hash(decodedPublicKey);
        const pemPublicKey = convertPublicKey(decodedPublicKey);
        const signature = decode(digitalProof.signature);
        const verify = cryptoRegistry.getVerifyFunction(target);

        return verify(data, pemPublicKey, signature);
    };

    target.getSecurityContext = () => {
        return _securityContext
    }

    target.setSecurityContext = (securityContext) => {
        _securityContext = securityContext
    }

    target.toJSON = function() {
        return target.getIdentifier();
    }
}

module.exports = keySSIMixin;
