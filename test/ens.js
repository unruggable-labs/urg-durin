import { solidityPackedKeccak256 } from "ethers/hash";

// https://etherscan.io/address/0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e#readContract
export const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";

export async function overrideENS(foundry, node, { owner, resolver = 0 }) {
	const slot = BigInt(
		solidityPackedKeccak256(["bytes32", "uint256"], [node, 0n])
	);
	const owner0 = BigInt(
		await foundry.provider.getStorage(ENS_REGISTRY, slot)
	);
	// https://github.com/foundry-rs/foundry/issues/9743
	await foundry.setStorageValue(ENS_REGISTRY, slot, owner || owner0 || 1);
	await foundry.setStorageValue(ENS_REGISTRY, slot + 1n, resolver || 0);
}
