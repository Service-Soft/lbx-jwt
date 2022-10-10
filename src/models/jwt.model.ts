
/**
 * A Json Web Token, containing the token itself and its expiration date.
 */
export interface Jwt {
    /**
     * The token value.
     */
    value: string,
    /**
     * The timestamp at which the token is no longer valid.
     */
    expirationDate: Date
}

/**
 * The payload of a jwt.
 */
export interface JwtPayload<RoleType extends string> {
    /**
     * The id of the user.
     */
    id: string,
    /**
     * The roles of the user.
     */
    roles: RoleType[]
}