const createSecretSSI = require("./SecretSSIs/SecretSSI").createSecretSSI;
const createAnchorSSI = require("./SecretSSIs/AnchorSSI").createAnchorSSI;
const createReadSSI = require("./SecretSSIs/ReadSSI").createReadSSI;
const createPublicSSI = require("./SecretSSIs/PublicSSI").createPublicSSI;
const createZaSSI = require("./SecretSSIs/ZaSSI").createZaSSI;
const createSeedSSI = require("./SeedSSIs/SeedSSI").createSeedSSI;
const createWalletSSI = require("./OtherKeySSIs/WalletSSI").createWalletSSI;
const createSReadSSI = require("./SeedSSIs/SReadSSI").createSReadSSI;
const createSZaSSI = require("./SeedSSIs/SZaSSI").createSZaSSI;
const createPasswordSSI = require("./ConstSSIs/PasswordSSI").createPasswordSSI;
const createArraySSI = require("./ConstSSIs/ArraySSI").createArraySSI;
const createConstSSI = require("./ConstSSIs/ConstSSI").createConstSSI;
const createCZaSSI = require("./ConstSSIs/CZaSSI").createCZaSSI;
const createHashLinkSSI = require("./OtherKeySSIs/HashLinkSSI").createHashLinkSSI;
const createSymmetricalEncryptionSSI = require("./OtherKeySSIs/SymmetricalEncryptionSSI").createSymmetricalEncryptionSSI;

const createTokenSSI = require("./TokenSSIs/TokenSSI").createTokenSSI;
const createOwnershipSSI = require("./OwnershipSSIs/OwnershipSSI").createOwnershipSSI;
const createOReadSSI = require("./OwnershipSSIs/OReadSSI").createOReadSSI;
const createZATSSI = require("./OwnershipSSIs/ZATSSI").createZATSSI;
const createTransferSSI = require("./TransferSSIs/TransferSSI").createTransferSSI;
const createSignedHashLinkSSI = require("./HashLinkSSIs/SignedHashLinkSSI").createSignedHashLinkSSI;

const createConsensusSSI = require("./ContractSSIs/ConsensusSSI").createConsensusSSI;
const createPublicKeySSI = require("./OtherKeySSIs/PublicKeySSI").createPublicKeySSI;

const SSITypes = require("./SSITypes");

const registry = {};

function KeySSIFactory() {
}

KeySSIFactory.prototype.registerFactory = (typeName, vn, derivedType, functionFactory) => {
    if (typeof derivedType === "function") {
        functionFactory = derivedType;
        derivedType = undefined;
    }

    if (typeof registry[typeName] !== "undefined") {
        throw Error(`A function factory for KeySSI of type ${typeName} is already registered.`);
    }

    registry[typeName] = {derivedType, functionFactory};
};

KeySSIFactory.prototype.create = (enclave, identifier, options) => {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }

    if (typeof identifier === "undefined") {
        throw Error("An SSI should be provided");
    }

    const KeySSIMixin = require("./KeySSIMixin");
    let keySSI = {}
    KeySSIMixin(keySSI, enclave);

    try{
        keySSI.autoLoad(identifier);
    }catch (e) {
        throw createOpenDSUErrorWrapper(`Invalid format for keySSI ${identifier}`, e);
    }

    const typeName = keySSI.getTypeName();

    return KeySSIFactory.prototype.createByType(typeName, enclave, identifier, options);
};

KeySSIFactory.prototype.createByType = (typeName, enclave, identifier, options) => {
    if (typeof enclave === "string") {
        identifier = enclave;
        enclave = undefined;
    }

    if (typeof identifier === "undefined") {
        throw Error("An SSI should be provided");
    }

    if (typeof registry[typeName] === "undefined") {
        throw Error(`The type ${typeName} is not a registered KeySSI type`);
    }
    const keySSI = registry[typeName].functionFactory(enclave, identifier);
    keySSI.options = options;
    return keySSI;
};

KeySSIFactory.prototype.createType = (typeName)=>{
    return registry[typeName].functionFactory();
}

KeySSIFactory.prototype.getRelatedType = (keySSI, otherType, callback) => {
    if (keySSI.getTypeName() === otherType) {
        return keySSI;
    }
    let currentEntry = registry[otherType];
    if (typeof currentEntry === "undefined") {
        return callback(Error(`${otherType} is not a registered KeySSI type.`))
    }

    while (typeof currentEntry.derivedType !== "undefined") {
        if (currentEntry.derivedType === keySSI.getTypeName()) {
            return $$.securityContext.getRelatedSSI(keySSI, otherType, callback);
        }
        currentEntry = registry[currentEntry.derivedType];
    }

    let derivedKeySSI;
    try {
        derivedKeySSI = getDerivedKeySSI(keySSI, otherType);
    } catch (err){
        return OpenDSUSafeCallback(callback)(createOpenDSUErrorWrapper(`Failed to retrieve derived type for keySSI`, err));
    }

    callback(undefined, derivedKeySSI);
};

KeySSIFactory.prototype.getAnchorType = (keySSI) => {
    let localKeySSI = keySSI;
    while (typeof registry[localKeySSI.getTypeName()].derivedType !== "undefined") {
        localKeySSI = localKeySSI.derive();
    }
    return localKeySSI;
};

KeySSIFactory.prototype.getRootKeySSITypeName = (keySSI) => {
    if (typeof keySSI === "object") {
        return KeySSIFactory.prototype.getRootKeySSITypeName(keySSI.getTypeName())
    }
    else if (typeof keySSI === "string") {
        let found = 0
        for (let parentKey in registry) {
            if (registry[parentKey].derivedType === keySSI) {
                found++
                return KeySSIFactory.prototype.getRootKeySSITypeName(parentKey)
            }
        }

        if (!found || found > 1) {
            return typeof keySSI === "object" ? keySSI.getTypeName() : keySSI
        }
    }
    else {
        return false
    }
}

const getDerivedKeySSI = (keySSI, derivedTypeName) => {
    let localKeySSI = keySSI;
    let currentEntry = registry[localKeySSI.getTypeName()];
    while (typeof currentEntry.derivedType !== "undefined") {
        if (currentEntry.derivedType === derivedTypeName) {
            return localKeySSI.derive();
        }
        localKeySSI = localKeySSI.derive();
        currentEntry = registry[currentEntry.derivedType];
    }

    throw Error(`${derivedTypeName} is not a valid KeySSI Type`);
};

KeySSIFactory.prototype.registerFactory(SSITypes.SECRET_SSI, 'v0', SSITypes.ANCHOR_SSI, createSecretSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.ANCHOR_SSI, 'v0', SSITypes.READ_SSI, createAnchorSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.READ_SSI, 'v0', SSITypes.PUBLIC_SSI, createReadSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.PUBLIC_SSI, 'v0', SSITypes.ZERO_ACCESS_SSI, createPublicSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.ZERO_ACCESS_SSI, 'v0', undefined, createZaSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.SEED_SSI, 'v0', SSITypes.SREAD_SSI, createSeedSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.WALLET_SSI, 'v0', SSITypes.CONST_SSI, createWalletSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.SREAD_SSI, 'v0', SSITypes.SZERO_ACCESS_SSI, createSReadSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.SZERO_ACCESS_SSI, 'v0', undefined, createSZaSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.PASSWORD_SSI, 'v0', SSITypes.CONST_SSI, createPasswordSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.ARRAY_SSI, 'v0', SSITypes.CONST_SSI, createArraySSI);
KeySSIFactory.prototype.registerFactory(SSITypes.CONST_SSI, 'v0', SSITypes.CONSTANT_ZERO_ACCESS_SSI, createConstSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.CONSTANT_ZERO_ACCESS_SSI, 'v0', undefined, createCZaSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.HASH_LINK_SSI, 'v0', undefined, createHashLinkSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.SYMMETRICAL_ENCRYPTION_SSI, 'v0', undefined, createSymmetricalEncryptionSSI);

KeySSIFactory.prototype.registerFactory(SSITypes.TOKEN_SSI, 'v0', undefined, createTokenSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.OWNERSHIP_SSI, 'v0', SSITypes.OWNERSHIP_READ_SSI, createOwnershipSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.OWNERSHIP_READ_SSI, 'v0', SSITypes.ZERO_ACCESS_TOKEN_SSI, createOReadSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.ZERO_ACCESS_TOKEN_SSI, 'v0', undefined, createZATSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.TRANSFER_SSI, 'v0', undefined, createTransferSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.SIGNED_HASH_LINK_SSI, 'v0', SSITypes.HASH_LINK_SSI, createSignedHashLinkSSI);

KeySSIFactory.prototype.registerFactory(SSITypes.CONSENSUS_SSI, 'v0', undefined, createConsensusSSI);
KeySSIFactory.prototype.registerFactory(SSITypes.PUBLIC_KEY_SSI, 'v0', undefined, createPublicKeySSI);

module.exports = new KeySSIFactory();
