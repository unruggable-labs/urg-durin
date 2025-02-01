// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GatewayFetcher, GatewayRequest} from "@unruggable/gateways/contracts/GatewayFetcher.sol";
import {GatewayFetchTarget, IGatewayVerifier} from "@unruggable/gateways/contracts/GatewayFetchTarget.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ENS} from "@ensdomains/ens-contracts/contracts/registry/ENS.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/contracts/resolvers/profiles/IExtendedResolver.sol";
import {INameWrapper} from "@ensdomains/ens-contracts/contracts/wrapper/INameWrapper.sol";
import {IAddrResolver} from "@ensdomains/ens-contracts/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ensdomains/ens-contracts/contracts/resolvers/profiles/IAddressResolver.sol";
import {ITextResolver} from "@ensdomains/ens-contracts/contracts/resolvers/profiles/ITextResolver.sol";
import {IContentHashResolver} from "@ensdomains/ens-contracts/contracts/resolvers/profiles/IContenthashResolver.sol";
import {BytesUtils} from "@ensdomains/ens-contracts/contracts/utils/BytesUtils.sol";

error Unauthorized();
error Unreachable();

// https://github.com/namestonehq/durin/blob/main/src/L2Registry.sol
uint256 constant SLOT_SUPPLY = 7;
uint256 constant SLOT_URI = 9;
uint256 constant SLOT_NAME = 10;
uint256 constant SLOT_TEXTS = 12;
uint256 constant SLOT_ADDRS = 13;
uint256 constant SLOT_CHASH = 14;

uint256 constant EVM_BIT = 1 << 31;

bytes4 constant SEL_SUPPLY = 0x00000001;

contract DurinResolver is IERC165, IExtendedResolver, Ownable, GatewayFetchTarget {
    using GatewayFetcher for GatewayRequest;
    using BytesUtils for bytes;

    ENS immutable _ens;
    INameWrapper immutable _wrapper;

    struct Link {
        address target;
        uint96 chainId;
        address verifier; // optional
        string[] gateways; // optional
    }

    mapping(uint96 => address) _verifiers;
    mapping(bytes32 => Link) _links;

    constructor(ENS ens, INameWrapper wrapper) Ownable(msg.sender) {
        _ens = ens;
        _wrapper = wrapper;
    }

    function supportsInterface(bytes4 x) external pure returns (bool) {
        return x == type(IERC165).interfaceId || x == type(IExtendedResolver).interfaceId;
    }

    function setVerifier(uint96 chainId, address verifier) external onlyOwner {
        _verifiers[chainId] = verifier;
    }

    function setLink(bytes32 node, uint96 chainId, address target, address verifier, string[] memory gateways)
        external
    {
        if (!_canModifyNode(node, msg.sender)) revert Unauthorized();
        Link storage link = _links[node];
        link.chainId = chainId;
        link.target = target;
        link.verifier = verifier;
        link.gateways = gateways;
    }

    function getLink(bytes32 node)
        external
        view
        returns (uint96 chainId, address verifier, address target, string[] memory gateways)
    {
        Link storage link = _links[node];
        chainId = link.chainId;
        target = link.target;
        verifier = link.verifier;
        gateways = link.gateways;
    }

    function _canModifyNode(bytes32 node, address op) internal view returns (bool) {
        address owner = _ens.owner(node);
        return owner == address(_wrapper)
            ? _wrapper.canModifyName(node, op)
            : (owner == op || _ens.isApprovedForAll(owner, op));
    }

    function resolve(bytes memory dns, bytes calldata request) external view returns (bytes memory) {
        (bytes32 basenode, uint256 offset) = _findSelf(dns);
        Link storage link = _links[basenode];
        if (link.target == address(0)) revert Unreachable(); // no target
        address verifier = link.verifier;
        if (verifier == address(0)) verifier = _verifiers[link.chainId];
        if (verifier == address(0)) revert Unreachable(); // no verifier
        bytes32 labelhash = _parseSubdomain(dns, offset);
        GatewayRequest memory req = GatewayFetcher.newRequest(1);
        req.setTarget(link.target);
        bytes4 selector = bytes4(request);
        if (selector == IAddrResolver.addr.selector) {
            if (labelhash == bytes32(0)) {
                return abi.encode(verifier);
            } else {
                req.setSlot(SLOT_ADDRS);
                req.push(labelhash).follow();
                req.push(60).follow();
                req.readBytes().setOutput(0);
            }
        } else if (selector == IAddressResolver.addr.selector) {
            (, uint256 coinType) = abi.decode(request[4:], (bytes32, uint256));
            if (labelhash == bytes32(0)) {
                if (coinType == 60) {
                    return abi.encode(abi.encodePacked(verifier));
                } else if (coinType == EVM_BIT | link.chainId) {
                    return abi.encode(abi.encodePacked(link.target));
                } else {
                    return abi.encode("");
                }
            } else {
                req.setSlot(SLOT_ADDRS);
                req.push(labelhash).follow();
                req.push(coinType).follow();
                req.readBytes().setOutput(0);
            }
        } else if (selector == ITextResolver.text.selector) {
            (, string memory key) = abi.decode(request[4:], (bytes32, string));
            bytes32 keyHash = keccak256(bytes(key));
            if (labelhash == bytes32(0)) {
                if (keyHash == keccak256("description")) {
                    req.setSlot(SLOT_SUPPLY);
                    req.read().setOutput(0);
                    selector = SEL_SUPPLY;
                } else if (keyHash == keccak256("name")) {
                    req.setSlot(SLOT_NAME);
                    req.readBytes().setOutput(0);
                } else if (keyHash == keccak256("url")) {
                    req.setSlot(SLOT_URI);
                    req.readBytes().setOutput(0);
                } else {
                    return abi.encode("");
                }
            } else {
                req.setSlot(SLOT_TEXTS);
                req.push(labelhash).follow();
                req.push(key).follow();
                req.readBytes().setOutput(0);
            }
        } else if (selector == IContentHashResolver.contenthash.selector) {
            if (labelhash == bytes32(0)) {
                return abi.encode("");
            } else {
                req.setSlot(SLOT_CHASH);
                req.push(labelhash).follow();
            }
        } else {
            return new bytes(64);
        }
        //req.debug("chonk");
        fetch(IGatewayVerifier(verifier), req, this.resolveCallback.selector, abi.encode(selector), link.gateways);
    }

    function resolveCallback(bytes[] memory values, uint8, /*exitCode*/ bytes memory carry)
        external
        pure
        returns (bytes memory)
    {
        bytes4 selector = abi.decode(carry, (bytes4));
        if (selector == IAddrResolver.addr.selector) {
            return abi.encode(uint160(bytes20(values[0])));
        } else if (selector == SEL_SUPPLY) {
            uint256 supply = uint256(bytes32(values[0]));
            return abi.encode(abi.encodePacked(Strings.toString(supply), " subdomains"));
        } else {
            return abi.encode(values[0]);
        }
    }

    function _parseSubdomain(bytes memory dns, uint256 offset) internal pure returns (bytes32 labelhash) {
        if (offset == 0) return bytes32(0);
        // support deep subdomains
        // dns = dns.substring(0, offset+2);
        // dns[offset] = bytes1(0);
        // dns[offset+1] = bytes1(0);
        // return dns.namehash(0);
        uint256 prev = 1;
        while (true) {
            uint256 next = prev + uint8(dns[prev - 1]);
            if (next == offset) {
                return dns.keccak(prev, next - prev);
            }
        }
    }

    function _findSelf(bytes memory dns) internal view returns (bytes32 node, uint256 offset) {
        unchecked {
            while (true) {
                node = dns.namehash(offset);
                if (_ens.resolver(node) == address(this)) break;
                uint256 size = uint8(dns[offset]);
                if (size == 0) revert Unreachable();
                offset += 1 + size;
            }
        }
    }
}
