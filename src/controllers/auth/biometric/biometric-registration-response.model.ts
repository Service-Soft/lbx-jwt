//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticatorAttachment, RegistrationResponseJSON } from '@simplewebauthn/types';

import { AuthenticationExtensionsOutputs } from './authentication-extensions-outputs.model';
import { AuthenticatorAttestationResponse } from './authenticator-attestation-response.model';
import { Base64UrlString, authenticatorAttachmentValues, publicKeyCredentialTypeValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class BiometricRegistrationResponse implements RegistrationResponseJSON {
    @property({
        type: 'string',
        required: true
    })
    id: Base64UrlString;

    @property({
        type: 'string',
        required: true
    })
    rawId: Base64UrlString;

    @property({
        type: AuthenticatorAttestationResponse,
        required: true
    })
    response: AuthenticatorAttestationResponse;

    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: authenticatorAttachmentValues
        }
    })
    authenticatorAttachment?: AuthenticatorAttachment;

    @property({
        type: AuthenticationExtensionsOutputs,
        required: true
    })
    clientExtensionResults: AuthenticationExtensionsOutputs;

    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: publicKeyCredentialTypeValues
        }
    })
    type: PublicKeyCredentialType;
}