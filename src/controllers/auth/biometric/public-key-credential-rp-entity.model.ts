//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { PublicKeyCredentialRpEntity as PublicKeyCredentialRpEntityInterface } from '@simplewebauthn/types';

@model()
export class PublicKeyCredentialRpEntity implements PublicKeyCredentialRpEntityInterface {
    @property({
        type: 'string',
        required: false
    })
    id?: string;

    @property({
        type: 'string',
        required: true
    })
    name: string;
}