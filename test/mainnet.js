import { Foundry } from "@adraffy/blocksmith";
import { ethers } from "ethers";
import { ENS_REGISTRY, overrideENS } from "./ens.js";

const foundry = await Foundry.launch({
	fork: "https://rpc.ankr.com/eth",
	infoLog: false,
});

const DurinResolver = await foundry.deploy({
	file: "DurinResolver",
	args: [
		ENS_REGISTRY,
		// https://etherscan.io/address/0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401#readContract
		"0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401",
	],
});

// https://gateway-docs.unruggable.com/verifiers/deployments
await foundry.confirm(
	DurinResolver.setVerifier(
		8453,
		"0x82304C5f4A08cfA38542664C5B78e1969cA49Cec"
	)
);

const BASENAME = "my.chonk";

await overrideENS(foundry, ethers.namehash(BASENAME), {
	owner: foundry.wallets.admin.address,
	resolver: DurinResolver.target,
});

await foundry.confirm(
	DurinResolver.setLink(
		ethers.namehash(BASENAME),
		8453,
		"0xd6322cFBCe33e24007134C017547495f150Deccd",
		ethers.ZeroAddress, // use default verifier for chain
		[] // use default gateways
	)
);

const resolver0 = await foundry.provider.getResolver(BASENAME);
console.log(await resolver0.getAddress());
console.log(await resolver0.getAddress(8453));
console.log(await resolver0.getText('name'));
console.log(await resolver0.getText('description'));

const resolver = await foundry.provider.getResolver(`slobo.${BASENAME}`);
console.log(await resolver.getAddress());

await foundry.shutdown();
