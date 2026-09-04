// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {AccessRegistry} from "./AccessRegistry.sol";

/**
 * @title CustodyLedger
 * @notice Immutable chain-of-custody log for legal documents.
 *         Every time a document changes hands or is accessed,
 *         an entry is recorded here for a full audit trail.
 */
contract CustodyLedger {
    // ── Types ─────────────────────────────────────────────────────
    enum ActionType {
        CREATED,        // Document first registered
        ACCESSED,       // Document viewed
        TRANSFERRED,    // Custody transferred to another party
        AMENDED,        // Document amended / new version
        SEALED          // Document sealed (no further changes)
    }

    struct CustodyEntry {
        bytes32    documentHash;
        ActionType action;
        address    actor;       // Who performed the action
        address    recipient;   // For TRANSFERRED: who received custody
        string     remarks;     // Free-text justification / notes
        uint256    timestamp;
        uint256    blockNumber;
    }

    // ── State ─────────────────────────────────────────────────────
    AccessRegistry public accessRegistry;

    // documentHash => ordered list of custody entries
    mapping(bytes32 => CustodyEntry[]) private _custodyTrail;

    // documentHash => current custodian address
    mapping(bytes32 => address) public currentCustodian;

    // documentHash => sealed flag
    mapping(bytes32 => bool) public isSealed;

    // ── Events ────────────────────────────────────────────────────
    event CustodyAction(
        bytes32 indexed documentHash,
        ActionType      action,
        address indexed actor,
        address indexed recipient,
        string          remarks,
        uint256         timestamp,
        uint256         blockNumber
    );

    // ── Errors ────────────────────────────────────────────────────
    error Unauthorized();
    error DocumentIsSealed(bytes32 documentHash);
    error NotCurrentCustodian(bytes32 documentHash, address caller);

    // ── Constructor ───────────────────────────────────────────────
    constructor(address _accessRegistry) {
        accessRegistry = AccessRegistry(_accessRegistry);
    }

    // ── Modifiers ─────────────────────────────────────────────────
    modifier onlyOfficerOrAdmin() {
        if (
            !accessRegistry.hasRole(accessRegistry.OFFICER_ROLE(), msg.sender) &&
            !accessRegistry.hasRole(accessRegistry.DEFAULT_ADMIN_ROLE(), msg.sender)
        ) {
            revert Unauthorized();
        }
        _;
    }

    modifier notSealed(bytes32 documentHash) {
        if (isSealed[documentHash]) {
            revert DocumentIsSealed(documentHash);
        }
        _;
    }

    // ── Core Functions ────────────────────────────────────────────

    /**
     * @notice Record the initial creation / registration of a document.
     *         Sets the caller as the first custodian.
     */
    function recordCreation(bytes32 documentHash, string calldata remarks)
        external
        onlyOfficerOrAdmin
        notSealed(documentHash)
    {
        currentCustodian[documentHash] = msg.sender;

        _pushEntry(documentHash, ActionType.CREATED, msg.sender, address(0), remarks);
    }

    /**
     * @notice Log that a document was accessed / viewed.
     */
    function recordAccess(bytes32 documentHash, string calldata remarks)
        external
        onlyOfficerOrAdmin
    {
        _pushEntry(documentHash, ActionType.ACCESSED, msg.sender, address(0), remarks);
    }

    /**
     * @notice Transfer custody of a document to another address.
     *         Only the current custodian (or admin) can transfer.
     */
    function transferCustody(
        bytes32 documentHash,
        address newCustodian,
        string calldata remarks
    ) external notSealed(documentHash) {
        if (
            msg.sender != currentCustodian[documentHash] &&
            !accessRegistry.hasRole(accessRegistry.DEFAULT_ADMIN_ROLE(), msg.sender)
        ) {
            revert NotCurrentCustodian(documentHash, msg.sender);
        }

        currentCustodian[documentHash] = newCustodian;

        _pushEntry(documentHash, ActionType.TRANSFERRED, msg.sender, newCustodian, remarks);
    }

    /**
     * @notice Record that a document was amended.
     */
    function recordAmendment(bytes32 documentHash, string calldata remarks)
        external
        onlyOfficerOrAdmin
        notSealed(documentHash)
    {
        _pushEntry(documentHash, ActionType.AMENDED, msg.sender, address(0), remarks);
    }

    /**
     * @notice Seal a document — no further custody changes or amendments allowed.
     *         Useful for finalized court judgments, etc.
     */
    function sealDocument(bytes32 documentHash, string calldata remarks)
        external
        onlyOfficerOrAdmin
        notSealed(documentHash)
    {
        isSealed[documentHash] = true;

        _pushEntry(documentHash, ActionType.SEALED, msg.sender, address(0), remarks);
    }

    // ── View Functions ────────────────────────────────────────────

    /**
     * @notice Get the full custody trail for a document.
     */
    function getCustodyTrail(bytes32 documentHash)
        external
        view
        returns (CustodyEntry[] memory)
    {
        return _custodyTrail[documentHash];
    }

    /**
     * @notice Get the total number of custody actions for a document.
     */
    function getCustodyTrailLength(bytes32 documentHash)
        external
        view
        returns (uint256)
    {
        return _custodyTrail[documentHash].length;
    }

    // ── Internal ──────────────────────────────────────────────────
    function _pushEntry(
        bytes32 documentHash,
        ActionType action,
        address actor,
        address recipient,
        string calldata remarks
    ) internal {
        _custodyTrail[documentHash].push(
            CustodyEntry({
                documentHash: documentHash,
                action: action,
                actor: actor,
                recipient: recipient,
                remarks: remarks,
                timestamp: block.timestamp,
                blockNumber: block.number
            })
        );

        emit CustodyAction(documentHash, action, actor, recipient, remarks, block.timestamp, block.number);
    }
}
