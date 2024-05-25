//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticationExtensionsClientInputs } from '@simplewebauthn/types';

@model()
export class AuthenticationExtensionsInputs implements AuthenticationExtensionsClientInputs {
    @property({
        type: 'string',
        required: false
    })
    appid?: string;

    @property({
        type: 'boolean',
        required: false
    })
    credProps?: boolean;

    @property({
        type: 'boolean',
        required: false
    })
    hmacCreateSecret?: boolean;
}