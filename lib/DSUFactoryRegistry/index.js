const BarFactory = require('./DSUFactory');
const SSITypes = require("../KeySSIs/SSITypes");
/**
 * @param {object} options
 * @param {BootstrapingService} options.bootstrapingService
 * @param {KeySSIFactory} options.keySSIFactory
 * @param {BrickMapStrategyFactory} options.brickMapStrategyFactory
 */
const factories = {};

function Registry(options) {
    options = options || {};

    const bootstrapingService = options.bootstrapingService;
    const keySSIFactory = options.keySSIFactory;
    const brickMapStrategyFactory = options.brickMapStrategyFactory

    if (!bootstrapingService) {
        throw new Error('BootstrapingService is required');
    }

    if (!keySSIFactory) {
        throw new Error('A KeySSI factory is required');
    }

    if (!brickMapStrategyFactory) {
        throw new Error('A BrickMapStratregy factory is required');
    }

    /**
     * Initialize the factory state
     */
    const initialize = () => {
        const barFactory = new BarFactory({
            bootstrapingService,
            keySSIFactory,
            brickMapStrategyFactory
        });

        this.registerDSUType(SSITypes.SEED_SSI, barFactory);
        this.registerDSUType(SSITypes.SREAD_SSI, barFactory);
        const WalletFactory = require("./WalletFactory");
        const walletFactory = new WalletFactory({barFactory});
        this.registerDSUType(SSITypes.WALLET_SSI, walletFactory);
        const ConstDSUFactory = require("./ConstDSUFactory");
        const constDSUFactory = new ConstDSUFactory({barFactory});
        this.registerDSUType(SSITypes.CONST_SSI, constDSUFactory);
        this.registerDSUType(SSITypes.ARRAY_SSI, constDSUFactory);

        this.registerDSUType(SSITypes.OWNERSHIP_SSI, barFactory);
        this.registerDSUType(SSITypes.OWNERSHIP_READ_SSI, barFactory);
    }

    ////////////////////////////////////////////////////////////
    // Public methods
    ////////////////////////////////////////////////////////////

    /**
     * @param {string} representation
     * @return {boolean}
     */
    this.isValidKeySSI = (keySSI) => {
        try{
            return typeof factories[keySSI.getTypeName()] !== 'undefined';
        } catch(err){
            return false;
        }
    };


    /**
     * @param {object} keySSI
     * @param {object} dsuConfiguration
     * @param {string} dsuConfiguration.brickMapStrategyFactory 'Diff', 'Versioned' or any strategy registered with the factory
     * @param {object} dsuConfiguration.anchoringOptions Anchoring options to pass to bar map strategy
     * @param {callback} dsuConfiguration.anchoringOptions.decisionFn Callback which will decide when to effectively anchor changes
     *                                                              If empty, the changes will be anchored after each operation
     * @param {callback} dsuConfiguration.anchoringOptions.conflictResolutionFn Callback which will handle anchoring conflicts
     *                                                              The default strategy is to reload the BrickMap and then apply the new changes
     * @param {callback} dsuConfiguration.anchoringOptions.anchoringCb A callback which is called when the strategy anchors the changes
     * @param {callback} dsuConfiguration.anchoringOptions.signingFn  A function which will sign the new alias
     * @param {object} dsuConfiguration.validationRules
     * @param {object} dsuConfiguration.validationRules.preWrite An object capable of validating operations done in the "preWrite" stage of the BrickMap
     * @param {callback} callback
     */
    this.create = (keySSI, dsuConfiguration, callback) => {
        let type = keySSI.getTypeName();
        if (keySSI.options && keySSI.options.dsuFactoryType) {
            type = keySSI.options.dsuFactoryType;
        }
        const factory = factories[type];
        factory.create(keySSI, dsuConfiguration, callback);
    }

    /**
     * @param {object} keySSI
     * @param {string} representation
     * @param {object} dsuConfiguration
     * @param {string} dsuConfiguration.brickMapStrategyFactory 'Diff', 'Versioned' or any strategy registered with the factory
     * @param {object} dsuConfiguration.anchoringOptions Anchoring options to pass to bar map strategy
     * @param {callback} dsuConfiguration.anchoringOptions.decisionFn Callback which will decide when to effectively anchor changes
     *                                                              If empty, the changes will be anchored after each operation
     * @param {callback} dsuConfiguration.anchoringOptions.conflictResolutionFn Callback which will handle anchoring conflicts
     *                                                              The default strategy is to reload the BrickMap and then apply the new changes
     * @param {callback} dsuConfiguration.anchoringOptions.anchoringCb A callback which is called when the strategy anchors the changes
     * @param {callback} dsuConfiguration.anchoringOptions.signingFn  A function which will sign the new alias
     * @param {object} dsuConfiguration.validationRules
     * @param {object} dsuConfiguration.validationRules.preWrite An object capable of validating operations done in the "preWrite" stage of the BrickMap
     * @param {callback} callback
     */
    this.load = (keySSI, dsuConfiguration, callback) => {
        let type = keySSI.getTypeName();
        if (keySSI.options && keySSI.options.dsuFactoryType) {
            type = keySSI.options.dsuFactoryType;
        }
        const factory = factories[type];
        return factory.load(keySSI, dsuConfiguration, callback);
    }

    initialize();
}

/**
 * @param {string} dsuType
 * @param {object} factory
 */
Registry.prototype.registerDSUType = (dsuType, factory) => {
    factories[dsuType] = factory;
}

Registry.prototype.getDSUFactory = (dsuType) => {
    return factories[dsuType];
}

module.exports = Registry;
