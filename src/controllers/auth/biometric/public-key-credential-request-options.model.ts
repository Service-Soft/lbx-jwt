/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { getJsonSchema } from '@loopback/rest';
import { PublicKeyCredentialRequestOptionsJSON, UserVerificationRequirement } from '@simplewebauthn/types';

import { AuthenticationExtensionsInputs } from './authentication-extensions-inputs.model';
import { PublicKeyCredentialDescriptor } from './public-key-credential-descriptor.model';
import { Base64UrlString, requirementValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class PublicKeyCredentialRequestOptions implements PublicKeyCredentialRequestOptionsJSON {
    @property({
        type: 'string',
        required: true
    })
    challenge: Base64UrlString;

    @property({
        type: 'number',
        required: false
    })
    timeout?: number;

    @property({
        type: 'string',
        required: false
    })
    rpId?: string;

    @property({
        type: 'array',
        itemType: 'object',
        required: false,
        jsonSchema: getJsonSchema(PublicKeyCredentialDescriptor)
    })
    allowCredentials?: PublicKeyCredentialDescriptor[];

    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: Object.values(requirementValues)
        }
    })
    userVerification?: UserVerificationRequirement;

    @property({
        type: AuthenticationExtensionsInputs,
        required: false
    })
    extensions?: AuthenticationExtensionsInputs;
}