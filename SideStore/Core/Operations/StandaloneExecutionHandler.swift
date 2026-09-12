//
//  StandaloneExecutionHandler.swift
//  SideStore
//
//  Created by Magesh K on 8/9/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign

protocol AnisetteServerHandler: AnyObject {
    func warnOutdatedAnisetteServer() async throws -> Bool
}

enum ProvisioningErrorDecision {
    case retry
    case cancel
}

enum RevokeDecision {
    case keepExisting
    case revokeSelected([ALTX509Certificate])
}

protocol SignInHandler: AnyObject {
    func credentials() async throws -> (String, String)
    func verificationCode(for request: TwoFactorRequest) async throws -> TwoFactorResponse
    /// Performs the WebAuthn assertion with the user's hardware security key
    /// when Apple demands one during sign-in. Implementations drive the
    /// platform authenticator UI and return the signed assertion for SideSign
    /// to submit to Apple, or throw (e.g. `DeveloperPortalError.userCancelled`)
    /// to abort the sign-in.
    func securityKeyAssertion(for challenge: SecurityKeyChallenge) async throws -> SecurityKeyAssertion
    func accountRepair(url: URL, message: String) async -> AccountRepairDecision
    func handleSignInResult(_ result: Result<(ALTAccount, ALTAppleAPISession), Error>) async
    
    func resolveTeam(_ teams: [ALTTeam]) async throws -> ALTTeam
    func resolveProvisioningError(_ error: Error) async -> ProvisioningErrorDecision
    func resolvePostAuth() async
    
    func resolveRevocation(certificates: [ALTX509Certificate], teamType: ALTTeamType) async throws -> RevokeDecision
    func resolveResign(mismatchReason: CodeSignValidationReason, context: StandaloneOperationContext) async throws -> Bool
    
    func complete() async
}

