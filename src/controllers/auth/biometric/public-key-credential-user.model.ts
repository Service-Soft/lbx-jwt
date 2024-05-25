//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { PublicKeyCredentialUserEntityJSON } from '@simplewebauthn/types';

@model()
export class PublicKeyCredentialUser implements PublicKeyCredentialUserEntityJSON {
    @property({
        type: 'string',
        required: true
    })
    id: string;

    @property({
        type: 'string',
        required: true
    })
    name: string;

    @property({
        type: 'string',
        required: true
    })
    displayName: string;
}