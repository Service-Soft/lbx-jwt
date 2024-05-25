/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticationResponseJSON, AuthenticatorAttachment } from '@simplewebauthn/types';

import { AuthenticationExtensionsOutputs } from './authentication-extensions-outputs.model';
import { AuthenticatorAssertionResponse } from './authenticator-assertion-response.model';
import { Base64UrlString, authenticatorAttachmentValues, publicKeyCredentialTypeValues } from '../../../encapsulation/webauthn.utilities';

/**
 * Response from the frontend when authentication was successful.
 */
@model()
export class AuthenticationResponse implements AuthenticationResponseJSON {
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
        type: AuthenticatorAssertionResponse,
        required: true
    })
    response: AuthenticatorAssertionResponse;

    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: Object.values(authenticatorAttachmentValues)
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

    @property({
        type: 'string',
        required: true
    })
    userId: string;
}