import { model, property } from '@loopback/repository';

/**
 * A Json Web Token, containing the token itself and its expiration date.
 */
@model()
export class Jwt {
    /**
     * The token value.
     */
    @property({
        type: 'string',
        required: true
    })
    value: string;
    /**
     * The timestamp at which the token is no longer valid.
     */
    @property({
        type: 'date',
        required: true
    })
    expirationDate: Date;
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