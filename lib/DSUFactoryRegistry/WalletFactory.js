/**
 * @param {object} options
 * @param {BootstrapingService} options.bootstrapingService
 * @param {KeySSIFactory} options.keySSIFactory
 * @param {BrickMapStrategyFactory} options.brickMapStrategyFactory
 */
function WalletFactory(options) {
    options = options || {};
    this.dsuFactory = options.barFactory;
    const WALLET_MOUNT_POINT = "/writableDSU";
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
        const defaultOpts = {overwrite: false};
        if (typeof options === 'function') {
            callback = options;
            options = {};
        }
        let writableWallet;
        let constDSUWallet;

        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let createWritableDSU = () => {
            let templateSSI = require("opendsu").loadApi("keyssi").buildSeedSSI(keySSI.getDLDomain());
            this.dsuFactory.create(templateSSI, (err, writableDSU) => {
                if (err) {
                    return callback(err);
                }
                writableWallet = writableDSU;
                mountDSUType();
            })
        }

        let mountDSUType = () =>{
            writableWallet.mount("/code", options.dsuTypeSSI, (err => {
                if (err) {
                    return callback(err);
                }
                createConstDSU();
            }));
        }



        let createConstDSU = () => {
            this.dsuFactory.create(keySSI, options, (err, constWallet) => {
                if (err) {
                    return callback(err);
                }

                constDSUWallet = constWallet;
                constDSUWallet.getWritableDSU = function(){
                    return writableWallet;
                }
                mountWritableWallet();
            })
        }


        let mountWritableWallet = () => {
            writableWallet.getKeySSI((err,seedSSI) =>{
                if (err) {
                    return callback(createOpenDSUErrorWrapper("Failed to get seedSSI",err));
                }
                constDSUWallet.mount(WALLET_MOUNT_POINT, seedSSI, (err => {
                    if (err) {
                        return callback(createOpenDSUErrorWrapper("Failed to mount writable SSI in wallet",err));
                    }
                    callback(undefined, constDSUWallet);
                }));
            });
        }

        createWritableDSU();
    };

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
        const defaultOpts = {overwrite: false};
        if (typeof options === 'function') {
            callback = options;
            options = {};
        }
        Object.assign(defaultOpts, options);
        options = defaultOpts;
        let constDSU;
        let writableDSU;
        let writableSSI;

        let loadConstDSU = () =>{
            this.dsuFactory.load(keySSI, options, (err, dsu) => {
                if (err) {
                    return callback(createOpenDSUErrorWrapper("Failed to load ConstDSU",err));
                }
                constDSU = dsu;
                getSSIFromMountPoint();
            });
        }


        let  getSSIFromMountPoint = () => {
            constDSU.getSSIForMount(WALLET_MOUNT_POINT, (err, ssi) => {
                if (err) {
                    return callback(createOpenDSUErrorWrapper("Failed to get mount point in ConstDSU",err));
                }
                writableSSI = require("opendsu").loadApi("keyssi").parse(ssi);
                loadWritableDSU();
            });
        }

        let loadWritableDSU = () => {
            this.dsuFactory.load(writableSSI, options, (err, dsu) => {
                if (err) {
                    return callback(createOpenDSUErrorWrapper("Failed to load writable DSU from ConstDSU Wallet", err));
                }
                writableDSU = dsu;
                constDSU.getWritableDSU = function(){
                    return writableDSU;
                }
                return callback(undefined, constDSU);
            });
        }


        loadConstDSU();

    };
}

module.exports = WalletFactory;