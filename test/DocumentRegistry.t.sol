// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {AccessRegistry} from "../src/AccessRegistry.sol";
import {AnchorRegistry} from "../src/AnchorRegistry.sol";
import {CustodyLedger} from "../src/CustodyLedger.sol";

contract LegalDMSTest is Test {
    AccessRegistry public accessRegistry;
    AnchorRegistry public anchorRegistry;
    CustodyLedger  public custodyLedger;

    address public admin   = address(1);
    address public officer = address(2);
    address public viewer  = address(3);
    address public nobody  = address(4);
    address public court   = address(5);

    // Pre-computed hashes used across tests
    bytes32 constant HASH1   = keccak256("hash1");
    bytes32 constant HASH2   = keccak256("hash2");
    bytes32 constant HASH3   = keccak256("hash3");
    bytes32 constant HASH123 = keccak256("hash123");
    bytes32 constant V1HASH  = keccak256("v1hash");
    bytes32 constant V2HASH  = keccak256("v2hash");
    bytes32 constant V3HASH  = keccak256("v3hash");
    bytes32 constant DOC1    = keccak256("doc1");
    bytes32 constant DOCA    = keccak256("docA");
    bytes32 constant ANYDOC  = keccak256("anyDoc");

    function setUp() public {
        vm.startPrank(admin);

        accessRegistry   = new AccessRegistry(admin);
        anchorRegistry   = new AnchorRegistry(address(accessRegistry));
        custodyLedger    = new CustodyLedger(address(accessRegistry));

        // Grant roles
        accessRegistry.addOfficer(officer);
        accessRegistry.addInvestigator(court);
        accessRegistry.addInvestigator(viewer);

        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════
    //  AccessRegistry Tests
    // ═══════════════════════════════════════════════════════════════

    function test_AR_AdminHasAdminRole() public view {
        assertTrue(accessRegistry.hasRole(accessRegistry.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_AR_OfficerHasOfficerRole() public view {
        assertTrue(accessRegistry.hasRole(accessRegistry.OFFICER_ROLE(), officer));
    }

    function test_AR_CourtHasCourtRole() public view {
        assertTrue(accessRegistry.hasRole(accessRegistry.INVESTIGATOR_ROLE(), court));
    }

    function test_AR_ViewerHasViewerRole() public view {
        assertTrue(accessRegistry.hasRole(accessRegistry.INVESTIGATOR_ROLE(), viewer));
    }

    function test_AR_AddCourtUser() public {
        address newCourt = address(10);
        vm.prank(admin);
        accessRegistry.addInvestigator(newCourt);
        assertTrue(accessRegistry.hasRole(accessRegistry.INVESTIGATOR_ROLE(), newCourt));
    }

    function test_AR_AddViewer() public {
        address newViewer = address(11);
        vm.prank(admin);
        accessRegistry.addInvestigator(newViewer);
        assertTrue(accessRegistry.hasRole(accessRegistry.INVESTIGATOR_ROLE(), newViewer));
    }

    function test_AR_RevertWhen_NonAdminAddsOfficer() public {
        vm.prank(nobody);
        vm.expectRevert();
        accessRegistry.addOfficer(address(99));
    }

    function test_AR_RevertWhen_NonAdminAddsCourtUser() public {
        vm.prank(nobody);
        vm.expectRevert();
        accessRegistry.addInvestigator(address(99));
    }

    function test_AR_RevertWhen_NonAdminAddsViewer() public {
        vm.prank(nobody);
        vm.expectRevert();
        accessRegistry.addInvestigator(address(99));
    }

    function test_AR_GrantDocumentAccess() public {
        vm.prank(officer);
        accessRegistry.grantDocumentAccess(DOC1, viewer);
        assertTrue(accessRegistry.hasDocumentAccess(DOC1, viewer));
    }

    function test_AR_RevokeDocumentAccess() public {
        vm.prank(officer);
        accessRegistry.grantDocumentAccess(DOC1, viewer);

        vm.prank(officer);
        accessRegistry.revokeDocumentAccess(DOC1, viewer);
        assertFalse(accessRegistry.hasDocumentAccess(DOC1, viewer));
    }

    function test_AR_RevertWhen_GrantAlreadyGrantedAccess() public {
        vm.startPrank(officer);
        accessRegistry.grantDocumentAccess(DOC1, viewer);

        vm.expectRevert(
            abi.encodeWithSelector(AccessRegistry.AccessAlreadyGranted.selector, DOC1, viewer)
        );
        accessRegistry.grantDocumentAccess(DOC1, viewer);
        vm.stopPrank();
    }

    function test_AR_RevertWhen_RevokeNotGrantedAccess() public {
        vm.prank(officer);
        vm.expectRevert(
            abi.encodeWithSelector(AccessRegistry.AccessNotGranted.selector, DOC1, viewer)
        );
        accessRegistry.revokeDocumentAccess(DOC1, viewer);
    }

    function test_AR_RevertWhen_NonOfficerGrantsAccess() public {
        vm.prank(nobody);
        vm.expectRevert();
        accessRegistry.grantDocumentAccess(DOC1, viewer);
    }

    function test_AR_RevertWhen_NonOfficerRevokesAccess() public {
        // First grant access
        vm.prank(officer);
        accessRegistry.grantDocumentAccess(DOC1, viewer);

        // Nobody tries to revoke
        vm.prank(nobody);
        vm.expectRevert();
        accessRegistry.revokeDocumentAccess(DOC1, viewer);
    }

    function test_AR_AdminAlwaysHasDocumentAccess() public view {
        assertTrue(accessRegistry.hasDocumentAccess(ANYDOC, admin));
    }

    function test_AR_OfficerAlwaysHasDocumentAccess() public view {
        assertTrue(accessRegistry.hasDocumentAccess(ANYDOC, officer));
    }

    function test_AR_NobodyHasNoAccessByDefault() public view {
        assertFalse(accessRegistry.hasDocumentAccess(ANYDOC, nobody));
    }

    // ═══════════════════════════════════════════════════════════════
    //  AnchorRegistry Tests
    // ═══════════════════════════════════════════════════════════════

    function test_AN_AnchorDocument() public {
        vm.prank(officer);
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");

        (bool exists, bytes32 docId, uint256 ts, uint256 blockNo, address uploader, uint256 version, string memory meta) =
            anchorRegistry.verifyDocument(HASH123);

        assertTrue(exists);
        assertEq(docId, HASH123);  // documentId == first hash
        assertEq(uploader, officer);
        assertEq(version, 1);
        assertEq(meta, "ipfs://meta");
        assertGt(ts, 0);
    }

    function test_AN_AdminCanAnchor() public {
        vm.prank(admin);
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");

        (bool exists,, ,, address uploader,,) = anchorRegistry.verifyDocument(HASH123);
        assertTrue(exists);
        assertEq(uploader, admin);
    }

    function test_AN_VerifyNonExistentDocument() public view {
        (bool exists, bytes32 docId, uint256 ts, uint256 blockNo, address uploader, uint256 version, string memory meta) =
            anchorRegistry.verifyDocument(keccak256("nonexistent"));

        assertFalse(exists);
        assertEq(docId, bytes32(0));
        assertEq(ts, 0);
        assertEq(uploader, address(0));
        assertEq(version, 0);
        assertEq(bytes(meta).length, 0);
    }

    function test_AN_RevertWhen_DuplicateAnchor() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");

        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.DocumentAlreadyAnchored.selector, HASH123)
        );
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta2");
        vm.stopPrank();
    }

    function test_AN_RevertWhen_UnauthorizedAnchor() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AnchorRegistry.Unauthorized.selector));
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");
    }

    function test_AN_AmendDocument() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");
        // documentId = V1HASH (the first anchored hash)
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
        vm.stopPrank();

        (bool exists, bytes32 docId,,, address uploader, uint256 version,) =
            anchorRegistry.verifyDocument(V2HASH);

        assertTrue(exists);
        assertEq(docId, V1HASH);  // linked back to original document
        assertEq(uploader, officer);
        assertEq(version, 2);
    }

    function test_AN_RevertWhen_AmendNonExistentDocument() public {
        bytes32 nonexistent = keccak256("nonexistent");
        vm.prank(officer);
        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.DocumentNotFound.selector, nonexistent)
        );
        anchorRegistry.amendDocument(nonexistent, V2HASH, "ipfs://v2");
    }

    function test_AN_RevertWhen_AmendToExistingHash() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");
        anchorRegistry.anchorDocument(V2HASH, "ipfs://v2");

        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.DocumentAlreadyAnchored.selector, V2HASH)
        );
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2amended");
        vm.stopPrank();
    }

    function test_AN_RevertWhen_UnauthorizedAmend() public {
        vm.prank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");

        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AnchorRegistry.Unauthorized.selector));
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
    }

    function test_AN_VersionChain() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
        anchorRegistry.amendDocument(V1HASH, V3HASH, "ipfs://v3");
        vm.stopPrank();

        bytes32[] memory chain = anchorRegistry.getVersionChain(V1HASH);
        assertEq(chain.length, 3);
        assertEq(chain[0], V1HASH);
        assertEq(chain[1], V2HASH);
        assertEq(chain[2], V3HASH);
    }

    function test_AN_GetVersionByNumber() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
        vm.stopPrank();

        AnchorRegistry.Anchor memory v1 = anchorRegistry.getVersion(V1HASH, 1);
        AnchorRegistry.Anchor memory v2 = anchorRegistry.getVersion(V1HASH, 2);

        assertEq(v1.version, 1);
        assertEq(v1.metadata, "ipfs://v1");
        assertEq(v1.documentHash, V1HASH);
        assertEq(v2.version, 2);
        assertEq(v2.metadata, "ipfs://v2");
        assertEq(v2.documentHash, V2HASH);
    }

    function test_AN_ReverseHashLookup() public {
        vm.startPrank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
        vm.stopPrank();

        assertEq(anchorRegistry.getDocumentId(V1HASH), V1HASH);
        assertEq(anchorRegistry.getDocumentId(V2HASH), V1HASH);
    }

    function test_AN_TotalDocuments() public {
        assertEq(anchorRegistry.totalDocuments(), 0);

        vm.startPrank(officer);
        anchorRegistry.anchorDocument(HASH1, "ipfs://m1");
        assertEq(anchorRegistry.totalDocuments(), 1);

        anchorRegistry.anchorDocument(HASH2, "ipfs://m2");
        assertEq(anchorRegistry.totalDocuments(), 2);

        anchorRegistry.amendDocument(HASH1, HASH3, "ipfs://m3");
        assertEq(anchorRegistry.totalDocuments(), 3);
        vm.stopPrank();
    }

    // ── Pausable Tests ────────────────────────────────────────────

    function test_AN_PauseBlocksAnchor() public {
        vm.prank(admin);
        anchorRegistry.pause();

        vm.prank(officer);
        vm.expectRevert();  // EnforcedPause
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");
    }

    function test_AN_PauseBlocksAmend() public {
        vm.prank(officer);
        anchorRegistry.anchorDocument(V1HASH, "ipfs://v1");

        vm.prank(admin);
        anchorRegistry.pause();

        vm.prank(officer);
        vm.expectRevert();  // EnforcedPause
        anchorRegistry.amendDocument(V1HASH, V2HASH, "ipfs://v2");
    }

    function test_AN_UnpauseResumesOperation() public {
        vm.prank(admin);
        anchorRegistry.pause();

        vm.prank(admin);
        anchorRegistry.unpause();

        vm.prank(officer);
        anchorRegistry.anchorDocument(HASH123, "ipfs://meta");

        (bool exists,,,,,,) = anchorRegistry.verifyDocument(HASH123);
        assertTrue(exists);
    }

    function test_AN_RevertWhen_NonAdminPauses() public {
        vm.prank(officer);
        vm.expectRevert(abi.encodeWithSelector(AnchorRegistry.Unauthorized.selector));
        anchorRegistry.pause();
    }

    function test_AN_RevertWhen_NonAdminUnpauses() public {
        vm.prank(admin);
        anchorRegistry.pause();

        vm.prank(officer);
        vm.expectRevert(abi.encodeWithSelector(AnchorRegistry.Unauthorized.selector));
        anchorRegistry.unpause();
    }

    // ═══════════════════════════════════════════════════════════════
    //  CustodyLedger Tests
    // ═══════════════════════════════════════════════════════════════

    function test_CL_RecordCreationSetsCustodian() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Initial filing");

        assertEq(custodyLedger.currentCustodian(DOCA), officer);
        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 1);
    }

    function test_CL_AdminCanRecordCreation() public {
        vm.prank(admin);
        custodyLedger.recordCreation(DOCA, "Admin filing");

        assertEq(custodyLedger.currentCustodian(DOCA), admin);
    }

    function test_CL_RevertWhen_UnauthorizedCreation() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CustodyLedger.Unauthorized.selector));
        custodyLedger.recordCreation(DOCA, "Unauthorized");
    }

    function test_CL_RecordAccess() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");

        vm.prank(officer);
        custodyLedger.recordAccess(DOCA, "Reviewed by IO");

        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 2);
    }

    function test_CL_RevertWhen_UnauthorizedAccess() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CustodyLedger.Unauthorized.selector));
        custodyLedger.recordAccess(DOCA, "Trying to log access");
    }

    function test_CL_TransferCustody() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Initial filing");

        vm.prank(officer);
        custodyLedger.transferCustody(DOCA, viewer, "Transferred for review");

        assertEq(custodyLedger.currentCustodian(DOCA), viewer);
        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 2);
    }

    function test_CL_AdminCanTransferCustody() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");

        // Admin can override and transfer even if not the current custodian
        vm.prank(admin);
        custodyLedger.transferCustody(DOCA, court, "Admin override transfer");

        assertEq(custodyLedger.currentCustodian(DOCA), court);
    }

    function test_CL_RevertWhen_NonCustodianTransfers() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Initial filing");

        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyLedger.NotCurrentCustodian.selector, DOCA, nobody)
        );
        custodyLedger.transferCustody(DOCA, nobody, "Trying to steal");
    }

    function test_CL_RecordAmendment() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");

        vm.prank(officer);
        custodyLedger.recordAmendment(DOCA, "Amended with new evidence");

        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 2);
    }

    function test_CL_RevertWhen_UnauthorizedAmendment() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");

        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CustodyLedger.Unauthorized.selector));
        custodyLedger.recordAmendment(DOCA, "Unauthorized amend");
    }

    function test_CL_SealDocument() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Case closed");
        vm.stopPrank();

        assertTrue(custodyLedger.isSealed(DOCA));
    }

    function test_CL_SealPreventsCreation() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Sealed");
        vm.stopPrank();

        vm.prank(officer);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyLedger.DocumentIsSealed.selector, DOCA)
        );
        custodyLedger.recordCreation(DOCA, "Trying to re-create");
    }

    function test_CL_SealPreventsAmendment() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Case closed");
        vm.stopPrank();

        vm.prank(officer);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyLedger.DocumentIsSealed.selector, DOCA)
        );
        custodyLedger.recordAmendment(DOCA, "Trying to amend sealed doc");
    }

    function test_CL_SealPreventsTransfer() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Sealed");
        vm.stopPrank();

        vm.prank(officer);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyLedger.DocumentIsSealed.selector, DOCA)
        );
        custodyLedger.transferCustody(DOCA, viewer, "Trying to transfer sealed");
    }

    function test_CL_SealPreventsSealingAgain() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Sealed");

        vm.expectRevert(
            abi.encodeWithSelector(CustodyLedger.DocumentIsSealed.selector, DOCA)
        );
        custodyLedger.sealDocument(DOCA, "Trying to seal again");
        vm.stopPrank();
    }

    function test_CL_RevertWhen_UnauthorizedSeal() public {
        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");

        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(CustodyLedger.Unauthorized.selector));
        custodyLedger.sealDocument(DOCA, "Unauthorized seal");
    }

    function test_CL_RecordAccessOnSealedDoc() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        custodyLedger.sealDocument(DOCA, "Sealed");
        vm.stopPrank();

        // recordAccess does NOT have notSealed modifier, so it should still work
        vm.prank(officer);
        custodyLedger.recordAccess(DOCA, "Viewing sealed doc");

        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 3);
    }

    function test_CL_FullCustodyTrail() public {
        vm.startPrank(officer);
        custodyLedger.recordCreation(DOCA, "Filed FIR");
        custodyLedger.recordAccess(DOCA, "Reviewed by IO");
        custodyLedger.recordAmendment(DOCA, "New evidence added");
        custodyLedger.transferCustody(DOCA, viewer, "Sent to court");
        vm.stopPrank();

        CustodyLedger.CustodyEntry[] memory trail = custodyLedger.getCustodyTrail(DOCA);

        assertEq(trail.length, 4);
        assertEq(uint(trail[0].action), uint(CustodyLedger.ActionType.CREATED));
        assertEq(uint(trail[1].action), uint(CustodyLedger.ActionType.ACCESSED));
        assertEq(uint(trail[2].action), uint(CustodyLedger.ActionType.AMENDED));
        assertEq(uint(trail[3].action), uint(CustodyLedger.ActionType.TRANSFERRED));
        assertEq(trail[3].recipient, viewer);
    }

    function test_CL_GetCustodyTrailLength() public {
        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 0);

        vm.prank(officer);
        custodyLedger.recordCreation(DOCA, "Filed");
        assertEq(custodyLedger.getCustodyTrailLength(DOCA), 1);
    }
}
