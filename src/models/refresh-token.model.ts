import { belongsTo, Entity, model, property } from '@loopback/repository';

import { BaseUser } from '.';

/**
 * Data about refresh tokens.
 */
@model()
export class RefreshToken extends Entity {

    /**
     * The id of the refresh token.
     */
    @property({
        type: 'string',
        required: true,
        defaultFn: 'uuidv4',
        id: true
    })
    id: string;

    /**
     * The id of the user to which this refresh token belongs.
     */
    @belongsTo(() => BaseUser)
    baseUserId: string;

    /**
     * The actual token value.
     */
    @property({
        type: 'string',
        required: true
    })
    tokenValue: string;

    /**
     * The id of the token family.
     * Is needed for the automatic reuse detection.
     */
    @property({
        type: 'string',
        required: true
    })
    familyId: string;

    /**
     * Whether or not the refresh token is blacklisted.
     * Is needed for the automatic reuse detection.
     */
    @property({
        type: 'boolean',
        required: true
    })
    blacklisted: boolean;

    /**
     * The expiration date of the refresh token.
     */
    @property({
        type: 'date',
        required: true
    })
    expirationDate: Date;

    constructor(data?: Partial<RefreshToken>) {
        super(data);
    }
}

/**
 * Properties of the entity relations.
 */
export interface RefreshTokenRelations {
    // describe navigational properties here
}

/**
 * The entity with its relation properties.
 */
export type RefreshTokenWithRelations = RefreshToken & RefreshTokenRelations;