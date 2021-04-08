const cryptoRegistry = require("./CryptoAlgorithmsRegistry");
const { BRICKS_DOMAIN_KEY } = require('opendsu').constants
const pskCrypto = require("pskcrypto");

const MAX_KEYSSI_LENGHT = 2048

function keySSIMixin(target){
    let _prefix = "ssi";
    let _subtype;
    let _dlDomain;
    let _subtypeSpecificString;
    let _control;
    let _vn = "v0";
    let _hint;
    let _hintObject = {};

    const _createHintObject = (hint = _hint) => {
        try {
            _hintObject = JSON.parse(hint)
        }
        catch (error) {
            //console.error('Parsing of hint failed, hint:', hint)
            _hintObject = {
                value:hint
            }
        }
    }

    const _inferJSON = (hintString) => {
        return hintString[0] === '{' || hintString[0] === '['
    }

    target.autoLoad = function (identifier) {
        if(typeof identifier === "undefined"){
            return;
        }

        if(typeof identifier !== "string"){
            throw new Error("The identifier should be string");
        }

        target.validateKeySSICharLength();

        let originalId = identifier;
        if(identifier.indexOf(":") === -1){
            identifier = pskCrypto.pskBase58Decode(identifier).toString();
        }

        if(identifier.indexOf(":") === -1){
            throw new Error(`Wrong format of SSI. ${originalId} ${identifier}`);
        }

        let segments = identifier.split(":");
        segments.shift();
        _subtype = segments.shift();
        _dlDomain = segments.shift();
        _subtypeSpecificString = segments.shift();
        _control = segments.shift();
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
        if (target.getIdentifier() > MAX_KEYSSI_LENGHT) {
            throw new Error(`The identifier length exceed maximum char length ${MAX_KEYSSI_LENGHT}`);
        }
    }

    target.load = function (subtype, dlDomain, subtypeSpecificString, control, vn, hint) {
        if ($$.Buffer.isBuffer(subtypeSpecificString)) {
            throw Error("Invalid subtypeSpecificString");
        }

        _subtype = subtype;
        _dlDomain = dlDomain;
        _subtypeSpecificString = subtypeSpecificString;
        _control = control;
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

    target.getAnchorId = function () {
        const keySSIFactory = require("./KeySSIFactory");
        return keySSIFactory.getAnchorType(target).getIdentifier();
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

    target.getControl = function () {
        return _control;
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

    target.getIdentifier = function (plain) {
        // const key = cryptoRegistry.getEncodingFunction(target)(_subtypeSpecificString);
        let id = `${_prefix}:${target.getTypeName()}:${_dlDomain}:${_subtypeSpecificString}:${_control}:${_vn}`;

        if (typeof _hint !== "undefined") {
            id += ":" + _hint;
        }

        return plain ? id : pskCrypto.pskBase58Encode(id);
    }

    target.getBricksDomain = function() {
        return _hintObject[BRICKS_DOMAIN_KEY] ? _hintObject[BRICKS_DOMAIN_KEY] : _dlDomain;
    }

    target.clone = function(){
        let clone = {};
        clone.prototype = target.prototype;
        for (let attr in target) {
            if (target.hasOwnProperty(attr)){
                clone[attr] = target[attr];
            }
        }
        keySSIMixin(clone);
        return clone;
    }

    target.cast = function(newType) {
        target.load(newType, _dlDomain, _subtypeSpecificString, _control, _vn, _hint);
    }

    target.toJSON = function() {
        return target.getIdentifier();
    }
}

module.exports = keySSIMixin;