import { Entity, model, property } from '@loopback/repository';

import { Base64UrlString } from '../encapsulation/webauthn.utilities';

/**
 * Biometric credentials of an user.
 */
@model()
export class BiometricCredentials extends Entity {

    /**
     * The id of the credentials.
     */
    @property({
        type: 'string',
        required: true,
        defaultFn: 'uuidv4',
        id: true
    })
    id: string;

    /**
     * The public key as a base64 string.
     */
    @property({
        type: 'string',
        required: true
    })
    publicKey: Base64UrlString;

    /**
     * The webauthn credential id as a base64 string.
     */
    @property({
        type: 'string',
        required: true
    })
    credentialId: Base64UrlString;

    /**
     * The webauthn challenge as a base64 string.
     */
    @property({
        type: 'string',
        required: true
    })
    challenge: Base64UrlString;

    /**
     * How many times the credentials have been used for this website.
     * Is used internally to prohibit replay attacks.
     */
    @property({
        type: 'number',
        required: true
    })
    counter: number;

    /**
     * The user that this credentials belong to.
     */
    @property({
        type: 'string',
        required: true
    })
    baseUserId: string;

    constructor(data?: Partial<BiometricCredentials>) {
        super(data);
    }
}

/**
 * Properties of the entity relations.
 */
export interface BiometricCredentialsRelations {
    // describe navigational properties here
}

/**
 * The entity with its relation properties.
 */
export type BiometricCredentialsWithRelations = BiometricCredentials & BiometricCredentialsRelations;