import { AuthorizationContext, AuthorizationDecision, AuthorizationMetadata } from '@loopback/authorization';

import { BaseUserProfile } from '../models';

/**
 * Checks if the requesting user has one of the allowed roles.
 * @param authorizationContext - The context, containing the user information.
 * @param metadata - The metadata, provided in the @authorize-decorator. Contains allowed roles.
 * @returns The promise of a decision (if the request is denied or approved).
 */
export async function roleAuthorization(
    authorizationContext: AuthorizationContext,
    metadata: AuthorizationMetadata
): Promise<AuthorizationDecision> {

    if (!authorizationContext.principals.length) {
        return AuthorizationDecision.DENY;
    }

    const userProfile: BaseUserProfile<string> = authorizationContext.principals[0] as BaseUserProfile<string>;
    if (userProfile.roles.find(r => metadata.allowedRoles?.includes(r))) {
        return AuthorizationDecision.ALLOW;
    }

    return AuthorizationDecision.DENY;
}