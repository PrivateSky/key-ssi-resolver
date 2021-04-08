/**
 * @param {object} options
 * @param {BootstrapingService} options.bootstrapingService
 * @param {KeySSIFactory} options.keySSIFactory
 * @param {BrickMapStrategyFactory} options.brickMapStrategyFactory
 */
const cache = require('psk-cache').factory();
function DSUFactory(options) {
    const barModule = require('bar');
    const fsAdapter = require('bar-fs-adapter');

    options = options || {};
    this.bootstrapingService = options.bootstrapingService;
    this.keySSIFactory = options.keySSIFactory;
    this.brickMapStrategyFactory = options.brickMapStrategyFactory;


    function castSSI(ssi){
        if(typeof ssi !== "undefined"){
            if(typeof ssi === "string"){
                let keyssi = require("opendsu").loadApi("keyssi");
                ssi = keyssi.parse(ssi);
            } else {
                 if(ssi.getTypeName === undefined || ssi.getIdentifier === undefined){
                     throw Error("Please provide a proper SSI instance ");
                 }
            }
        } else {
            throw Error("SSI should not be undefined");
        }
        return ssi;
    }

    let forcedArchiveSingletonsCache = {};


    ////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////

    /**
     * @param {SeedSSI} keySSI
     * @param {object} options
     * @return {Archive}
     */
    const createInstance = (keySSI, options) => {
        let identifier = keySSI;
        if(typeof identifier == "string"){
            let bar = forcedArchiveSingletonsCache[identifier];
            if(bar) return bar;
        }

        const ArchiveConfigurator = barModule.ArchiveConfigurator;
        ArchiveConfigurator.prototype.registerFsAdapter("FsAdapter", fsAdapter.createFsAdapter);
        const archiveConfigurator = new ArchiveConfigurator();
        archiveConfigurator.setCache(cache);
        const envTypes = require("overwrite-require").constants;
        if($$.environmentType !== envTypes.BROWSER_ENVIRONMENT_TYPE && 
            $$.environmentType !== envTypes.SERVICE_WORKER_ENVIRONMENT_TYPE &&
            $$.environmentType !== envTypes.WEB_WORKER_ENVIRONMENT_TYPE){
            archiveConfigurator.setFsAdapter("FsAdapter");
        }
        archiveConfigurator.setBufferSize(1000000);
        archiveConfigurator.setKeySSI(keySSI);
        archiveConfigurator.setBootstrapingService(this.bootstrapingService);
        let brickMapStrategyName = options.brickMapStrategy;
        let anchoringOptions = options.anchoringOptions;
        let brickMapStrategy;
        try {
            brickMapStrategy = createBrickMapStrategy(brickMapStrategyName, anchoringOptions);

            archiveConfigurator.setBrickMapStrategy(brickMapStrategy);

            if (options.validationRules) {
                archiveConfigurator.setValidationRules(options.validationRules);
            }
        }catch(e) {
            throw e;
        }

        const bar = barModule.createArchive(archiveConfigurator);
        const DSUBase = require("./mixins/DSUBase");
        DSUBase(bar);
        forcedArchiveSingletonsCache[identifier] = bar;
        return bar;
    }

    /**
     * @return {object}
     */
    const createBrickMapStrategy = (name, options) => {
        const strategy = this.brickMapStrategyFactory.create(name, options);
        return strategy;
    }

    /**
     * @return {SecretDID}
     * @param templateKeySSI
     * @param callback
     */
    const initializeKeySSI = (templateKeySSI, callback) => {
        if (typeof templateKeySSI === "function") {
            callback = templateKeySSI;
            templateKeySSI = undefined;
        }

        if (typeof templateKeySSI === "undefined") {
            return callback(Error("A template keySSI should be provided when creating a new DSU."));
        }
        const KeySSIFactory = require("../KeySSIs/KeySSIFactory");
        const keySSI = KeySSIFactory.createType(templateKeySSI.getTypeName());
        keySSI.initialize(templateKeySSI.getDLDomain(), undefined, undefined, undefined, templateKeySSI.getHint(), callback);
    }

    ////////////////////////////////////////////////////////////
    // Public methods
    ////////////////////////////////////////////////////////////

    /**
     * @param {object} options
     * @param {string} options.brickMapStrategy 'Diff', 'Versioned' or any strategy registered with the factory
     * @param {object} options.anchoringOptions Anchoring options to pass to bar map strategy
     * @param {callback} options.anchoringOptions.decisionFn Callback which will decide when to effectively anchor changes
     *                                                              If empty, the changes will be anchored after each operation
     * @param {callback} options.anchoringOptions.conflictResolutionFn Callback which will handle anchoring conflicts
     *                                                              The default strategy is to reload the BrickMap and then apply the new changes
     * @param {callback} options.anchoringOptions.anchoringEventListener An event listener which is called when the strategy anchors the changes
     * @param {callback} options.anchoringOptions.signingFn  A function which will sign the new alias
     * @param {object} options.validationRules
     * @param {object} options.validationRules.preWrite An object capable of validating operations done in the "preWrite" stage of the BrickMap
     * @param {callback} callback
     */
    this.create = (keySSI, options, callback) => {
        keySSI = castSSI(keySSI);
        if(typeof options === "function"){
            callback = options;
            options = undefined;
        }
        options = options || {};
        if (options.useSSIAsIdentifier) {
            let bar;
            try {
                bar = createInstance(keySSI, options);
            } catch (err) {
                return OpenDSUSafeCallback(callback)(createOpenDSUErrorWrapper(`Failed to create DSU instance`, err));
            }
            return bar.init(err => callback(err, bar));
        }

        initializeKeySSI(keySSI, (err, _keySSI) => {
            if (err) {
                return OpenDSUSafeCallback(callback)(createOpenDSUErrorWrapper(`Failed to initialize keySSI <${keySSI.getIdentifier(true)}>`, err));
            }

            let bar;
            try {
                bar = createInstance(_keySSI, options);
            } catch (err) {
                return OpenDSUSafeCallback(callback)(createOpenDSUErrorWrapper(`Failed to create DSU instance`, err));
            }
            bar.init(err => callback(err, bar));
        });
    }

    /**
     * @param {string} keySSI
     * @param {object} options
     * @param {string} options.brickMapStrategy 'Diff', 'Versioned' or any strategy registered with the factory
     * @param {object} options.anchoringOptions Anchoring options to pass to bar map strategy
     * @param {callback} options.anchoringOptions.decisionFn Callback which will decide when to effectively anchor changes
     *                                                              If empty, the changes will be anchored after each operation
     * @param {callback} options.anchoringOptions.conflictResolutionFn Callback which will handle anchoring conflicts
     *                                                              The default strategy is to reload the BrickMap and then apply the new changes
     * @param {callback} options.anchoringOptions.anchoringEventListener An event listener which is called when the strategy anchors the changes
     * @param {callback} options.anchoringOptions.signingFn  A function which will sign the new alias
     * @param {object} options.validationRules
     * @param {object} options.validationRules.preWrite An object capable of validating operations done in the "preWrite" stage of the BrickMap
     * @param {callback} callback
     */
    this.load = (keySSI, options, callback) => {
        keySSI = castSSI(keySSI);
        if(typeof options === "function"){
            callback = options;
            options = undefined;
        }
        options = options || {};
        let bar;
        try {
            bar = createInstance(keySSI, options);
        } catch (err) {
            return OpenDSUSafeCallback(callback)(createOpenDSUErrorWrapper(`Failed to create DSU instance`, err));
        }
        bar.load(err => callback(err, bar));
    }
}

module.exports = DSUFactory;
