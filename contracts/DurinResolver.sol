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

    /// Constant address paths for ENS contracts
    ENS immutable _ens;
    INameWrapper immutable _wrapper;

    /// A struct definition that contains resolution configuration for a node (namehash)
    /// Using Unruggable Gateways for trustless data resolution
    struct Link {
        address target;
        uint96 chainId;
        IGatewayVerifier verifier; // optional
        string[] gateways; // optional
    }

    /// Mapping of default verifiers for a chain ID
    mapping(uint96 => IGatewayVerifier) _verifiers;

    /// Mapping of ENS node (namehash) representations to their resolution configuration
    mapping(bytes32 => Link) _links;

    constructor(ENS ens, INameWrapper wrapper) Ownable(msg.sender) {
        _ens = ens;
        _wrapper = wrapper;
    }

    function supportsInterface(bytes4 x) external pure returns (bool) {
        /// We confirm implementation of ERC165 for interface discovery, and ENSIP-10 for wildcard resolution
        return x == type(IERC165).interfaceId || x == type(IExtendedResolver).interfaceId;
    }

    /**
     * @notice Define the appropriate default Unruggable Gateway Verifier with a chainId
     */
    function setVerifier(uint96 chainId, IGatewayVerifier verifier) external onlyOwner {
        _verifiers[chainId] = verifier;
    }

    /**
     * @notice Set resolution configuration data for a specified ENS node (namehash)
     */
    function setLink(bytes32 node, uint96 chainId, address target, IGatewayVerifier verifier, string[] memory gateways)
        external
        onlyNodeOperator(node)
    {
        _links[node] = Link(target, chainId, verifier, gateways);
    }

    /**
     * @notice Get resolution configuration data for a specified ENS node (namehash)
     */
    function getLink(bytes32 node)
        external
        view
        returns (address target, uint96 chainId, IGatewayVerifier verifier, string[] memory gateways)
    {
        Link storage link = _links[node];
        target = link.target;
        chainId = link.chainId;
        verifier = link.verifier;
        gateways = link.gateways;
    }

    /**
     * @notice Discern if an address owns the node in the ENS registry (or NameWrapper)
     */
    function _canModifyNode(bytes32 node, address op) internal view returns (bool) {
        address owner = _ens.owner(node);
        return owner == address(_wrapper)
            ? _wrapper.canModifyName(node, op)
            : (owner == op || _ens.isApprovedForAll(owner, op));
    }

    modifier onlyNodeOperator(bytes32 node) {
        if (!_canModifyNode(node, msg.sender)) revert Unauthorized();
        _;
    }

    /**
     * @notice Implementation of ENSIP-10 that allows for resolution
     * @param dns - The DNS encoded representation of the name
     * @param request - The calldata for the request
     */
    function resolve(bytes memory dns, bytes calldata request) external view returns (bytes memory) {
        /// Find the node for which THIS contract is the resolver
        (bytes32 basenode, uint256 offset) = _findSelf(dns);
        /// Get the resolution configuration for that node
        Link storage link = _links[basenode];
        if (link.target == address(0)) revert Unreachable(); // no target
        IGatewayVerifier verifier = link.verifier;
        /// If no verifier is set for that node specifically, use the chain default
        if (address(verifier) == address(0)) {
            verifier = _verifiers[link.chainId];
            /// If no chain default, we cannot continue
            if (address(verifier) == address(0)) revert Unreachable();
        }
        /// Get the labelhash of the base node for which this contract is the resolver
        bytes32 labelhash = _parseSubdomain(dns, offset);
        GatewayRequest memory req = GatewayFetcher.newRequest(1);
        req.setTarget(link.target);
        bytes4 selector = bytes4(request);
        /// Build a Unruggable Gateways request based on the function selector of the passed calldata
        /// ENSIP-1: addr
        if (selector == IAddrResolver.addr.selector) {
            if (labelhash == bytes32(0)) {
                return abi.encode(verifier);
            } else {
                /// We want to read data from the mapping with a slot root `SLOT_ADDRS` defined within the Durin contracts
                req.setSlot(SLOT_ADDRS);
                /// Push the labelhash, and follow. Builds the slot ID of `mapping[labelhash]`
                req.push(labelhash).follow();
                /// Push the ETH cointype (60), and follow. Builds the slot ID of `mapping[labelhash][60]`
                req.push(60).follow();
                /// Read the address and set it in output 0 of the return data passed to our CCIP read callback
                req.readBytes().setOutput(0);
            }

            /// ENSIP-9?: addr(node, coinType)
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
                /// We want to read data from the mapping with a slot root `SLOT_ADDRS` defined within the Durin contracts
                req.setSlot(SLOT_ADDRS);
                /// Push the labelhash, and follow. Builds the slot ID of `mapping[labelhash]`
                req.push(labelhash).follow();
                /// Push the cointype decoded from the target calldata, and follow. Builds the slot ID of `mapping[labelhash][coinType]`
                req.push(coinType).follow();
                /// Read the address and set it in output 0 of the return data passed to our CCIP read callback
                req.readBytes().setOutput(0);
            }
            /// ENSIP-5: text(node, key)
        } else if (selector == ITextResolver.text.selector) {
            /// Decode the key from the target calldata. We already have the DNS encoded representation of the name.
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

            /// ENSIP-?: contenthash
        } else if (selector == IContentHashResolver.contenthash.selector) {
            if (labelhash == bytes32(0)) {
                return abi.encode("");
            } else {
                req.setSlot(SLOT_CHASH);
                req.push(labelhash).follow();
                req.readBytes().setOutput(0);
            }
            /// Unsupported selector - return zero bytes
        } else {
            return new bytes(64);
        }
        /// Execute the Unruggable Gateways CCIP request
        /// Pass through the called function selector in our carry bytes such that the callback can appropriately decode the response
        fetch(verifier, req, this.resolveCallback.selector, abi.encode(selector), link.gateways);
    }

    /**
     * @notice The callback for the `OffchainLookup` triggered by our implementation of `IExtendedResolver` (ENSIP-10)
     */
    function resolveCallback(bytes[] memory values, uint8, /*exitCode*/ bytes memory carry)
        external
        pure
        returns (bytes memory)
    {
        bytes4 selector = abi.decode(carry, (bytes4));
        /// If we have an address as bytes, re-encode it correctly for decoding at the library level
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
        /// End of the encoding, no labelhash
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

    /**
     * @notice ENSIP-10 hones down the subname tree until it finds a defined resolver. This internal helper returns the node (namehash) of the name for which THIS contract is the resolver
     * @param dns The DNS encoded name
     * @return node The node (namehash) in the subname tree for which the resolver is set
     * @return offset The offset in the encoded name at which that node begins
     */
    function _findSelf(bytes memory dns) internal view returns (bytes32 node, uint256 offset) {
        unchecked {
            while (true) {
                /// Get the namehash for the name splitting it based on the current offset
                /// The recursive nature of this call will yield a response for sub.name.eth, then name.eth etc until broken
                node = dns.namehash(offset);
                /// We break the loop when we find the level at which THIS contract is the resolver
                if (_ens.resolver(node) == address(this)) break;
                uint256 size = uint8(dns[offset]);
                if (size == 0) revert Unreachable();
                offset += 1 + size;
            }
        }
    }
}
