//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';

import { Base64UrlString } from '../../../encapsulation/webauthn.utilities';

@model()
export class UvmAuthenticatorOutput {
    @property({
        type: 'array',
        itemType: 'string',
        required: false
    })
    uvm?: Base64UrlString[];
}