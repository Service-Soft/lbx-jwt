import { model, property } from '@loopback/repository';
import { getJsonSchema } from '@loopback/rest';

import { BiometricCredentials } from '../../../models';

/**
 * The response for finalizing a biometric registration.
 */
@model()
export class ConfirmBiometricRegistrationResponse {
    /**
     * All biometric credentials of the user, including the new one if registration was successful.
     */
    @property({
        type: 'array',
        itemType: 'object',
        required: false,
        jsonSchema: getJsonSchema(BiometricCredentials)
    })
    biometricCredentials: BiometricCredentials[];
    /**
     * Whether or not registration was successful.
     */
    @property({
        type: 'boolean',
        required: true
    })
    verified: boolean;
}