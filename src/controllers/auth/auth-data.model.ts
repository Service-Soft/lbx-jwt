import { inject } from '@loopback/core';
import { Model, model, property } from '@loopback/repository';
import { getJsonSchema } from '@loopback/rest';

import { LbxJwtBindings } from '../../keys';
import { BiometricCredentials, Jwt } from '../../models';

/**
 * The authentication data that is send to the user.
 * This is needed eg. To Display navigation elements only if the user has the required role.
 */
@model()
export class AuthData<RoleType extends string> extends Model {
    /**
     * The token used for authenticating requests.
     * Consists of the string value and the expirationDate value.
     */
    @property({
        type: Jwt,
        required: true
    })
    accessToken: Jwt;
    /**
     * The token used for refreshing the access token.
     * Consists of the string value and the expirationDate value.
     */
    @property({
        type: Jwt,
        required: true
    })
    refreshToken: Jwt;
    /**
     * All roles of the currently logged in user.
     * Consists of an displayName and the actual string value.
     */
    @property({
        type: 'array',
        itemType: 'string',
        required: true
        // json schema restricting to certain roles is set in constructor.
    })
    roles: RoleType[];
    /**
     * Whether or not two factor authentication is enabled.
     */
    @property({
        type: 'boolean',
        required: true
    })
    twoFactorEnabled: boolean;
    /**
     * The biometric credentials of the user.
     * This is an array because a user might have multiple devices with a fingerprint sensor.
     */
    @property({
        type: 'array',
        itemType: 'object',
        required: false,
        jsonSchema: getJsonSchema(BiometricCredentials)
    })
    biometricCredentials: BiometricCredentials[];
    /**
     * The id of the currently logged in user.
     */
    @property({
        type: 'string',
        required: true
    })
    userId: string;

    /**
     * Helper for defining the roles open api.
     */
    @inject(LbxJwtBindings.ROLES)
    private readonly roleValues: RoleType[];

    constructor(data?: Partial<AuthData<RoleType>>) {
        super(data);
        AuthData.definition.properties['roles'].jsonSchema = {
            items: {
                enum: this.roleValues
            }
        };
    }
}