//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';

import { Base64UrlString } from '../../../encapsulation/webauthn.utilities';

@model()
export class DevicePublicKeyAuthenticatorOutput {
    @property({
        type: 'string',
        required: false
    })
    dpk?: Base64UrlString;

    @property({
        type: 'string',
        required: false
    })
    sig?: string;

    @property({
        type: 'string',
        required: false
    })
    nonce?: Base64UrlString;

    @property({
        type: 'string',
        required: false
    })
    scope?: Base64UrlString;

    @property({
        type: 'string',
        required: false
    })
    aaguid?: Base64UrlString;
}