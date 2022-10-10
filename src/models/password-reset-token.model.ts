import { model, property, belongsTo, Entity } from '@loopback/repository';
import { BaseUser } from './base-user.model';

/**
 * Contains info about a password reset token.
 */
@model()
export class PasswordResetToken extends Entity {

    /**
     * The id of the reset token.
     */
    @property({
        type: 'string',
        required: true,
        defaultFn: 'uuidv4',
        id: true
    })
    id: string;

    /**
     * The expiration date of the password reset token.
     */
    @property({
        type: 'date',
        required: true
    })
    expirationDate: Date;

    /**
     * The actual token value.
     */
    @property({
        type: 'string',
        required: true
    })
    value: string;

    /**
     * The base user to which this token belongs.
     */
    @belongsTo(() => BaseUser)
    baseUserId: string;

    constructor(data?: Partial<PasswordResetToken>) {
        super(data);
    }
}

/**
 * Properties of the entity relations.
 */
export interface PasswordResetTokenRelations {
    // describe navigational properties here
}

/**
 * The entity with its relation properties.
 */
export type PasswordResetTokenWithRelations = PasswordResetToken & PasswordResetTokenRelations;