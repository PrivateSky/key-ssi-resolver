'use strict';

function SimpleAnchorVerificationStrategy(options) {
    options = options || {};

    let barMapController;
    let sessionBarMap = null;

    ////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////

    /**
     * Assemble a final BarMap from several BarMapDiffs
     *
     * @param {Array<string>} hashes
     * @param {callback} callback
     */
    const assembleBarMap = (hashes, callback) => {
        barMapController.getMultipleBricks(hashes, (err, bricks) => {
            if (err) {
                return callback(err);
            }

            if (hashes.length !== bricks.length) {
                return callback(new Error('Invalid data received'));
            }

            const barMap = barMapController.createNewBarMap();
            try {
                for (const brick of bricks) {
                    const barMapDiff = barMapController.createNewBarMap(brick);
                    barMap.applyDiff(barMapDiff);
                }
            } catch (e) {
                return callback(e);
            }

            callback(undefined, barMap);
        })
    }

    /**
     * @param {BarMapController} controller
     */
    this.setBarMapController = (controller) => {
        barMapController = controller;
    }

    /**
     * Load and assemble the BarMap identified by `alias`
     *
     * @param {string} alias
     * @param {callback} callback
     */
    this.loadBarMap = (alias, callback) => {
        barMapController.getAliasVersions(alias, (err, versionHashes) => {
            if (err) {
                return callback(err);
            }

            if (!versionHashes.length) {
                return callback(new Error(`No data found for alias <${id}>`));
            };

            assembleBarMap(versionHashes, callback);
        });
    }

    /**
     * @return {SessionBarMap}
     */
    this.beginSession = () => {
        sessionBarMap = barMapController.createSessionBarMap();
        return sessionBarMap;
    }

    /**
     * @return {boolean}
     */
    this.sessionIsStarted = () => {
        return sessionBarMap !== null;
    }

    this.endSession = () => {
        sessionBarMap = null;
    }

    /**
     * @param {string} operation
     * @param {string} path
     * @param {object} options
     * @param {callback} callback
     */
    this.validatePreWrite = (operation, path, options, callback) => {
        if (typeof options === 'function') {
            callback = options;
            options = {};
        }

        callback();
    }

    /**
     * @param {BarMapDiff} diff
     * @param {callback} callback
     */
    this.afterBarMapUpdate = (diff, callback) => {
        callback();
    }

    /**
     * Anchor each change
     * @param {callback} callback
     */
    this.doAnchoring = (callback) => {
        barMapController.saveSession(sessionBarMap, (err, hash) => {
            if (err) {
                return callback(err);
            }

            this.afterBarMapUpdate(sessionBarMap.getDiff(), (err) => {
                if (err) {
                    return callback(err);
                }
                this.endSession();
                const result = {
                    sessionEnded: true,
                    hash
                };
                callback(undefined, result);
            })

        })
    }
}

module.exports = SimpleAnchorVerificationStrategy;