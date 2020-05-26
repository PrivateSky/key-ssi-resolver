'use strict';

require('../../../psknode/bundles/testsRuntime');
require('../../../psknode/bundles/edfsBar');

const tir = require('../../../psknode/tests/util/tir.js');
const testUtils = require('./utils');

const dc = require("double-check");
const assert = dc.assert;

const DSU_REPRESENTATIONS = require('../lib/constants').BUILTIN_DSU_REPR;
const KeyDIDResolver = require('../lib/KeyDIDResolver');
const BootstrapingService = require('../lib/BootstrapingService').Service;

const options = {
    endpointsConfiguration: {
        brickEndpoints: [
            {
                endpoint: 'http://localhost:8081',
                protocol: 'EDFS',
            },
            {
                endpoint: 'http://localhost:8002',
                protocol: 'EDFS'
            },
            {
                // placeholder will be replaced after a server node
                // is started
                endpoint: 'http://localhost:{port}',
                protocol: 'EDFS' // working endpoint
            }
        ],
        aliasEndpoints: [
            {
                endpoint: 'http://localhost:8081',
                protocol: 'EDFS'
            },
            {
                endpoint: 'http://localhost:8000',
                protocol: 'EDFS'
            },
            {
                // placeholder will be replaced after a server node
                // is started
                endpoint: 'http://localhost:{port}',
                protocol: 'EDFS' // working endpoint
            }
        ]
    },
    dlDomain: 'localDomain'
};

let bootstrapingService;
let keyDidResolver;
let favouriteEndpoint = 'http://localhost:{port}';

testUtils.createTestFolder('load_bar_test_folder', (err, testFolder) => {
    assert.true(err === null || typeof err === 'undefined', 'Failed to create test folder');

    assert.callback('Load Bar Test', (done) => {
        tir.launchVirtualMQNode(10, testFolder, (err, serverPort) => {
            assert.true(err === null || typeof err === 'undefined', 'Failed to create server');

            testUtils.setValidPort(serverPort, options.endpointsConfiguration, 2);
            favouriteEndpoint = favouriteEndpoint.replace('{port}', serverPort);

            bootstrapingService = new BootstrapingService(options.endpointsConfiguration);
            keyDidResolver = new KeyDIDResolver({
                bootstrapingService,
                dlDomain: 'local'
            });

            createBar((err, did) => {
                assert.true(typeof err === 'undefined', 'DSU is writable');
                runTest(did, done);
            });
        })
    }, 2000);
});

function createBar(callback) {
    keyDidResolver.createDSU(DSU_REPRESENTATIONS.RawDossier, {
        favouriteEndpoint
    }, (err, dsu) => {

        assert.true(typeof err === 'undefined', 'No error while creating the DSU');
        assert.true(dsu.constructor.name === 'RawDossier', 'DSU has the correct class');

        dsu.writeFile('my-file.txt', 'Lorem Ipsum', (err, hash) => {
            callback(err, dsu.getDID());
        })
    });
}

function runTest(did, callback) {
    keyDidResolver.loadDSU(did, DSU_REPRESENTATIONS.RawDossier, (err, dsu) => {
        assert.true(typeof err === 'undefined', 'No error while loading the DSU');

        dsu.readFile('my-file.txt', (err, data) => {
            assert.true(typeof err === 'undefined', 'No error while reading file from DSU');

            assert.true(data.toString() === 'Lorem Ipsum', 'File has the correct content');
            callback();
        });
    });
}

