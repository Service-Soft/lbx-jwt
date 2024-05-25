//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticatorTransportFuture, PublicKeyCredentialDescriptorJSON } from '@simplewebauthn/types';

import { Base64UrlString, authenticatorTransportFutureValues, publicKeyCredentialTypeValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class PublicKeyCredentialDescriptor implements PublicKeyCredentialDescriptorJSON {
    @property({
        type: 'string',
        required: true
    })
    id: Base64UrlString;

    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: publicKeyCredentialTypeValues
        }
    })
    type: PublicKeyCredentialType;

    @property({
        itemType: 'string',
        required: false,
        jsonSchema: {
            enum: authenticatorTransportFutureValues
        }
    })
    transports?: AuthenticatorTransportFuture[];
}