/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticatorAssertionResponseJSON } from '@simplewebauthn/types';

import { Base64UrlString } from '../../../encapsulation/webauthn.utilities';

@model()
export class AuthenticatorAssertionResponse implements AuthenticatorAssertionResponseJSON {
    @property({
        type: 'string',
        required: true
    })
    clientDataJSON: Base64UrlString;

    @property({
        type: 'string',
        required: true
    })
    authenticatorData: Base64UrlString;

    @property({
        type: 'string',
        required: true
    })
    signature: Base64UrlString;

    @property({
        type: 'string',
        required: false
    })
    userHandle?: Base64UrlString;

}