// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {AccessRegistry} from "./AccessRegistry.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AnchorRegistry
 * @notice Stores document hashes on-chain as tamper-proof anchors.
 *         Actual documents live off-chain (IPFS / cloud); only the hash
 *         is recorded here for integrity verification.
 *
 *         Each logical document is identified by a stable `documentId`
 *         (equal to the first anchored hash). Amendments append new
 *         hashes to the same document's version chain.
 */
contract AnchorRegistry is Pausable {
    // ── Types ─────
    struct Anchor {
        bytes32 documentHash;   // SHA-256 or keccak256 hash of the document
        bytes32 documentId;     // Stable identifier (= first hash of the document)
        string  metadata;       // JSON metadata URI
        uint256 timestamp;
        uint256 blockNumber;    // Block number when it was anchored
        address uploader;
        uint256 version;        // starts at 1, increments on amendment
    }

    // ── State ─────────────────────────────────────────────────────
    AccessRegistry public accessRegistry;

    // hash => Anchor (every hash ever anchored)
    mapping(bytes32 => Anchor) private _anchors;

    // documentId => ordered list of version hashes
    mapping(bytes32 => bytes32[]) private _versionHashes;

    // hash => documentId (reverse lookup: find which document a hash belongs to)
    mapping(bytes32 => bytes32) private _hashToDocId;

    // Simple counter (no unbounded array)
    uint256 private _totalAnchors;

    // ── Events ────────────────────────────────────────────────────
    event DocumentAnchored(
        bytes32 indexed documentHash,
        bytes32 indexed documentId,
        address indexed uploader,
        uint256 version,
        uint256 timestamp,
        uint256 blockNumber
    );

    event DocumentAmended(
        bytes32 indexed documentId,
        bytes32 indexed newHash,
        address indexed amendedBy,
        uint256 newVersion,
        uint256 timestamp,
        uint256 blockNumber
    );

    // NOTE: Paused/Unpaused events are inherited from OpenZeppelin Pausable

    // ── Errors ────────────────────────────────────────────────────
    error DocumentAlreadyAnchored(bytes32 documentHash);
    error DocumentNotFound(bytes32 documentId);
    error Unauthorized();

    // ── Constructor ───────────────────────────────────────────────
    constructor(address _accessRegistry) {
        accessRegistry = AccessRegistry(_accessRegistry);
    }

    // ── Modifiers ─────────────────────────────────────────────────
    modifier onlyOfficer() {
        if (
            !accessRegistry.hasRole(accessRegistry.OFFICER_ROLE(), msg.sender) &&
            !accessRegistry.hasRole(accessRegistry.DEFAULT_ADMIN_ROLE(), msg.sender)
        ) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyAdmin() {
        if (!accessRegistry.hasRole(accessRegistry.DEFAULT_ADMIN_ROLE(), msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    // ── Pausable Controls ─────────────────────────────────────────

    /**
     * @notice Emergency pause — blocks new anchors and amendments.
     */
    function pause() external onlyAdmin {
        _pause();
    }

    /**
     * @notice Resume normal operation.
     */
    function unpause() external onlyAdmin {
        _unpause();
    }

    // ── Core Functions ────────────────────────────────────────────

    /**
     * @notice Anchor a new document hash on-chain.
     *         Creates a new documentId (= the hash itself) and starts
     *         a fresh version chain.
     * @param _documentHash  The hash of the document (SHA-256 / keccak256).
     * @param _metadata      A URI pointing to additional metadata (JSON).
     */
    function anchorDocument(bytes32 _documentHash, string calldata _metadata)
        external
        onlyOfficer
        whenNotPaused
    {
        if (_anchors[_documentHash].timestamp != 0) {
            revert DocumentAlreadyAnchored(_documentHash);
        }

        // documentId = first hash (stable across all versions)
        bytes32 docId = _documentHash;

        Anchor memory anchor = Anchor({
            documentHash: _documentHash,
            documentId: docId,
            metadata: _metadata,
            timestamp: block.timestamp,
            blockNumber: block.number,
            uploader: msg.sender,
            version: 1
        });

        _anchors[_documentHash] = anchor;
        _versionHashes[docId].push(_documentHash);
        _hashToDocId[_documentHash] = docId;
        _totalAnchors++;

        emit DocumentAnchored(_documentHash, docId, msg.sender, 1, block.timestamp, block.number);
    }

    /**
     * @notice Amend an existing document by anchoring a new hash
     *         under the same documentId.
     * @param _documentId  The stable document identifier (= first hash).
     * @param _newHash     The hash of the amended document.
     * @param _metadata    Updated metadata URI.
     */
    function amendDocument(
        bytes32 _documentId,
        bytes32 _newHash,
        string calldata _metadata
    ) external onlyOfficer whenNotPaused {
        // documentId must exist (at least version 1 was anchored)
        if (_versionHashes[_documentId].length == 0) {
            revert DocumentNotFound(_documentId);
        }
        if (_anchors[_newHash].timestamp != 0) {
            revert DocumentAlreadyAnchored(_newHash);
        }

        uint256 newVersion = _versionHashes[_documentId].length + 1;

        Anchor memory anchor = Anchor({
            documentHash: _newHash,
            documentId: _documentId,
            metadata: _metadata,
            timestamp: block.timestamp,
            blockNumber: block.number,
            uploader: msg.sender,
            version: newVersion
        });

        _anchors[_newHash] = anchor;
        _versionHashes[_documentId].push(_newHash);
        _hashToDocId[_newHash] = _documentId;
        _totalAnchors++;

        emit DocumentAmended(_documentId, _newHash, msg.sender, newVersion, block.timestamp, block.number);
    }

    // ── View Functions ────────────────────────────────────────────

    /**
     * @notice Verify whether a document hash exists on-chain.
     */
    function verifyDocument(bytes32 _documentHash)
        external
        view
        returns (
            bool    exists,
            bytes32 documentId,
            uint256 timestamp,
            uint256 blockNumber,
            address uploader,
            uint256 version,
            string memory metadata
        )
    {
        Anchor memory a = _anchors[_documentHash];
        if (a.timestamp == 0) {
            return (false, bytes32(0), 0, 0, address(0), 0, "");
        }
        return (true, a.documentId, a.timestamp, a.blockNumber, a.uploader, a.version, a.metadata);
    }

    /**
     * @notice Get the full ordered version chain for a document.
     * @param _documentId The stable document identifier.
     * @return hashes Array of all version hashes in chronological order.
     */
    function getVersionChain(bytes32 _documentId)
        external
        view
        returns (bytes32[] memory hashes)
    {
        return _versionHashes[_documentId];
    }

    /**
     * @notice Retrieve a specific version's anchor by document ID and version number.
     * @param _documentId The stable document identifier.
     * @param _version    1-indexed version number.
     */
    function getVersion(bytes32 _documentId, uint256 _version)
        external
        view
        returns (Anchor memory)
    {
        require(_version > 0 && _version <= _versionHashes[_documentId].length, "Invalid version");
        bytes32 hash = _versionHashes[_documentId][_version - 1];
        return _anchors[hash];
    }

    /**
     * @notice Reverse-lookup: find which documentId a hash belongs to.
     */
    function getDocumentId(bytes32 _hash) external view returns (bytes32) {
        return _hashToDocId[_hash];
    }

    /**
     * @notice Get total number of anchored hashes (across all documents & versions).
     */
    function totalDocuments() external view returns (uint256) {
        return _totalAnchors;
    }
}
