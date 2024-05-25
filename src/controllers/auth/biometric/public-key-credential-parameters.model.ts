//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { PublicKeyCredentialParameters as PublicKeyCredentialParametersInterface } from '@simplewebauthn/types';

import { publicKeyCredentialTypeValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class PublicKeyCredentialParameters implements PublicKeyCredentialParametersInterface {
    @property({
        type: 'number',
        required: true
    })
    alg: number;

    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: publicKeyCredentialTypeValues
        }
    })
    type: PublicKeyCredentialType;
}