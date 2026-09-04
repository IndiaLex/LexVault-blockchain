// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";


/**
 * @title AccessRegistry
 * @notice Manages role-based access control for the Legal DMS.
 *         Handles global roles (ADMIN, OFFICER, INVESTIGATOR)
 *         and per-document access grants.
 */


contract AccessRegistry is AccessControl {

    // ── Global Roles ──

    bytes32 public constant OFFICER_ROLE = keccak256("OFFICER_ROLE");
    bytes32 public constant INVESTIGATOR_ROLE   = keccak256("INVESTIGATOR_ROLE");

    // ── Per-Document Access ───
    // documentHash => user address => granted?
    mapping(bytes32 => mapping(address => bool)) private _documentAccess;

    // ── Events ───
    event DocumentAccessGranted(bytes32 indexed documentHash, address indexed user, address indexed grantedBy);
    event DocumentAccessRevoked(bytes32 indexed documentHash, address indexed user, address indexed revokedBy);

    // ── Errors ───
    error AccessAlreadyGranted(bytes32 documentHash, address user);
    error AccessNotGranted(bytes32 documentHash, address user);

    constructor(address initialAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(OFFICER_ROLE, initialAdmin);
    }

    // ── Global Role Management (admin-only helpers) ─────

    function addOfficer(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(OFFICER_ROLE, account);
    }

    function addInvestigator(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(INVESTIGATOR_ROLE, account);
    }

    // ── Per-Document Access ───────────────────────────────────────

    /**
     * @notice Grant a specific user access to a specific document.
     *         Only OFFICER or ADMIN can grant access.
     */
    function grantDocumentAccess(bytes32 documentHash, address user)
        external
        onlyRole(OFFICER_ROLE)
    {
        if (_documentAccess[documentHash][user]) {
            revert AccessAlreadyGranted(documentHash, user);
        }
        _documentAccess[documentHash][user] = true;
        emit DocumentAccessGranted(documentHash, user, msg.sender);
    }

    /**
     * @notice Revoke a specific user's access to a specific document.
     */
    function revokeDocumentAccess(bytes32 documentHash, address user)
        external
        onlyRole(OFFICER_ROLE)
    {
        if (!_documentAccess[documentHash][user]) {
            revert AccessNotGranted(documentHash, user);
        }
        _documentAccess[documentHash][user] = false;
        emit DocumentAccessRevoked(documentHash, user, msg.sender);
    }

    /**
     * @notice Check whether a user has access to a given document.
     *         Admins and Officers always have access; others need an explicit grant.
     */
    function hasDocumentAccess(bytes32 documentHash, address user)
        external
        view
        returns (bool)
    {
        if (hasRole(DEFAULT_ADMIN_ROLE, user) || hasRole(OFFICER_ROLE, user)) {
            return true;
        }
        return _documentAccess[documentHash][user];
    }
}
