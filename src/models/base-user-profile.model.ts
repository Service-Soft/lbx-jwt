import { UserProfile, securityId } from '@loopback/security';

/**
 * A User Profile type to provide more type safety.
 */
export class BaseUserProfile<RoleType extends string> implements UserProfile {
    /**
     * The id of the user.
     */
    [securityId]: string;
    /**
     * The id of the user.
     */
    id: string;
    /**
     * The roles of the user.
     */
    roles: RoleType[];
    /**
     * The email of the user.
     */
    email: string;
}