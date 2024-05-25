//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticatorAttestationResponseJSON, AuthenticatorTransportFuture } from '@simplewebauthn/types';

import { Base64UrlString, authenticatorTransportFutureValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class AuthenticatorAttestationResponse implements AuthenticatorAttestationResponseJSON {
    @property({
        type: 'string',
        required: true
    })
    clientDataJSON: Base64UrlString;

    @property({
        type: 'string',
        required: true
    })
    attestationObject: Base64UrlString;

    @property({
        type: 'string',
        required: false
    })
    authenticatorData?: Base64UrlString;

    @property({
        itemType: 'string',
        required: false,
        jsonSchema: {
            enum: authenticatorTransportFutureValues
        }
    })
    transports?: AuthenticatorTransportFuture[];

    @property({
        type: 'number',
        required: false
    })
    publicKeyAlgorithm?: number;

    @property({
        type: 'string',
        required: false
    })
    publicKey?: Base64UrlString;

}