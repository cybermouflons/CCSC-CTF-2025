/*
 * Blockchain Challenge
 */


// Load Libraries
const fs = require("fs");
const solc = require('solc');
const path = require('path');
const Web3 = require("web3");
const bip39 = require("bip39");
const ganache = require("ganache");
const Wallet = require('ethereumjs-wallet').default;
const HDkey = require('ethereumjs-wallet').hdkey;
const express = require('express');
const nunjucks = require('nunjucks');
const { createProxyMiddleware } = require('http-proxy-middleware');


// Load Flag
let flag = 'HTB{example-flag}';
flag = fs.readFileSync(path.join(__dirname, 'flag')).toString();


/* Generate Addresses
 ------------------------------*/

// Generate a custom address for the server
// This will be used to deploy the smart contract and make action from the server side
const server_wallet = (() => {
	const wallet = Wallet.generate();
	return {
		address: wallet.getAddressString(),
		privateKey: wallet.getPrivateKeyString(),
		initial_ballance: Web3.utils.toHex(Web3.utils.toWei('1010', 'ether'))
	};
})();


// Generate a custom address for the client/player
// To be used by the client/player for interacting with the blockchain
const client_wallet = (() => {
	const mnemonic = bip39.generateMnemonic();
	const hdwallet = HDkey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
	// from BIP44, HD derivation path is:
	// m / purpose’ / coin_type’ / account’ / change / address_index
	const path = "m/44'/60'/0'/0/0";
	const wallet = hdwallet.derivePath(path).getWallet();
	return {
		mnemonic: mnemonic,
		address: wallet.getAddressString(),
		privateKey: wallet.getPrivateKeyString(),
		initial_ballance: Web3.utils.toHex(Web3.utils.toWei('10', 'ether'))
	};
})(Wallet.generate());


/* Smart contract informations
 ------------------------------*/
let contract_info = {
	name : 'Blackjack',

	folder_path : 'static',
	filename_sol : 'contract.sol',
	libs_import : {
		'Math.sol' : 'Math.sol',
	},
	filename_bin : 'contract.bin',
	filename_abi : 'contract.abi',

	compiled : false,
	deployed : false,

	address : null,
	abi_string : null
};



// Allow running with await
(async () => {

	/* Ganache blockchain
	 ------------------------------*/
	let ganache_info = {
		gasLimit : Web3.utils.toWei('0.012', 'gwei'),
		defaultAccountBalance : Web3.utils.toHex(Web3.utils.toWei('0', 'ether')),
		running : false,
	};

	const options = {
		chain: {
			chainId: 0x4242
		},
		wallet: {
			accounts: [
				// Wallet for the Server
				{
					secretKey: server_wallet.privateKey,
					balance: server_wallet.initial_ballance
				},
				// Wallet for the client
				{
					secretKey: client_wallet.privateKey,
					balance: client_wallet.initial_ballance
				}
			],
			defaultBalance: ganache_info.defaultAccountBalance
		},
		server: {
			ws: false,
			host: '127.0.0.1',
			port: 8545,
			rpcEndpoint: '/blockchain'
		},
		logging : {
			quiet : true,
			verbose : false
		},
		miner : {
			blockGasLimit: Web3.utils.toHex(ganache_info.gasLimit)
		}
	};

	// Start ganache blockchain provider
	const server = ganache.server(options);
	// Get Web3 provider
	const web3 = new Web3(server.provider);



	/* Deploy Ganache
	 ------------------------------*/
	server.listen(options.server.port, err => {
		if (err) throw err;
		console.log(`Ganache listening on port ${options.server.port}...`);
		ganache_info.running = true;
	});



	/* Deploy Web service
	 ------------------------------*/
	const app = express();
	nunjucks.configure('views', {
		autoescape: true,
		express: app
	});
	app.use('/static', express.static(path.join(__dirname, 'static')));

	// Blockchain Endpoint
	app.use(options.server.rpcEndpoint, createProxyMiddleware({
		target: 'http://' + options.server.host + ':' + options.server.port,
		//changeOrigin: true,
		//ws: true,
		logLevel : 'error'
	}));

	// Web application endpoint
	app.get('/', (req, res) => {
		if (!ganache_info.running || !contract_info.deployed) {
			res.render('loading.html');
		}
		else {
			res.render('index.html', {
				ganache_info,
				server_wallet,
				client_wallet,
				contract_info,
				ganache_options : options
			});
		}
	});

	app.get('/check', (req, res) => {
		if (!ganache_info.running || !contract_info.deployed) {
			res.json({error: 'Challenge is still loading ...'});
		}
		else {
			// Check if the condition was met to get the smart contract
			web3.eth.getBalance(contract_info.address).then(
				balance => {
					if (balance === '0') {
						res.json({success: 'Well done! Here is your flag: ' + flag});
					}
					else {
						res.json({error: 'The contract has ' + Web3.utils.fromWei(balance, 'ether') + ' ether. Keep trying.'});
					}
				}
			)
			.catch(
				err => {
					console.log(err);
					res.json({error: 'Unknown error.'});
				}
			);
		}
	});

	app.listen(4242, '0.0.0.0');



	/* Prepare & Deploy Contract
	 ------------------------------*/
	((info) => {
		return new Promise(function(resolve, reject) {
			// Compile smart contract if not already compiled
			if (!info.compiled) {
				const source = fs.readFileSync(path.resolve(__dirname, info.folder_path, info.filename_sol), 'UTF-8');

				const compiled_info = JSON.parse(
					solc.compile(
						JSON.stringify({
							language: 'Solidity',
							sources: {
								'contract.sol': {content: source}
							},
							settings: {
								outputSelection: {
									'*': {
										'*': ['*']
									}
								}
							}
						}),
						{
							import: (import_path) => {
								if (info.libs_import.hasOwnProperty(import_path))
									return {
										contents: fs.readFileSync(path.resolve(__dirname, info.folder_path, info.libs_import[import_path]), 'UTF-8')
									};
								else return {
									error: 'File not found'
								};
							}
						}
					)
				);
				if (compiled_info.errors) {
					// Print any errors or warnings
					console.log('Contract compiler errors', compiled_info.errors.map(err => `[${err.severity}] ${err.type}: ${err.message}`));

					if (compiled_info.errors.filter(err => err.severity == 'error').length > 0) {
						reject('Compile error!');
						return;
					}
				}
				const compiled = compiled_info.contracts['contract.sol'][info.name];
				info.compiled = {
					abi : compiled.abi,
					bytecode : compiled.evm.bytecode.object
				};
				info.abi_string = JSON.stringify(compiled.abi).replace(/</g, '\\u003c');

				fs.writeFileSync(path.resolve(__dirname, info.folder_path, info.filename_bin), info.compiled.bytecode);
				fs.writeFileSync(path.resolve(__dirname, info.folder_path, info.filename_abi), JSON.stringify(info.compiled.abi));
			}

			// Load contract files
			const bytecode = info.compiled.bytecode;
			//fs.readFileSync(path.join(__dirname, 'static', info.filename_bin)).toString();
			const abi = info.compiled.abi;
			//JSON.parse(fs.readFileSync(path.join(__dirname, 'static', info.filename_abi)).toString());

			// Create contract
			const contract = new web3.eth.Contract(abi);

			// Smart contract arguments
			const seed = Web3.utils.randomHex(32);

			// Deploy and return
			resolve(
				contract.deploy({
					data: bytecode,
					arguments: [seed]
				})
			);
		});
	})(contract_info)
	.then(async (contract) => {
		contract.send({
			from: server_wallet.address,
			gas: (await contract.estimateGas()) * 2,
			value: Web3.utils.toHex(Web3.utils.toWei('1000', 'ether')),
		})
		.on('error', function(error){
			// Report Error
			console.log('Contract creation error', error);
		})
		.then(function(contract){
			console.log('Contract deployed at address', contract.options.address);
			contract_info.address = contract.options.address;
			contract_info.deployed = true;
		});
	})
	.catch(error => {
		console.log('Error', error);
	});

})();
