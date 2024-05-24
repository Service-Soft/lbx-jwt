//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticationExtensionsClientOutputs } from '@simplewebauthn/types';

import { BiometricCredentialPropertiesOutput } from './credential-properties-output.model';

@model()
export class AuthenticationExtensionsOutputs implements AuthenticationExtensionsClientOutputs {
    @property({
        type: 'string',
        required: false
    })
    appid?: boolean;

    @property({
        type: BiometricCredentialPropertiesOutput,
        required: true
    })
    credProps?: BiometricCredentialPropertiesOutput;

    @property({
        type: 'boolean',
        required: false
    })
    hmacCreateSecret?: boolean;
}