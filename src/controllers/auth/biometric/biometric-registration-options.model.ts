//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { getJsonSchema } from '@loopback/rest';
import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/types';

import { AuthenticationExtensionsInputs } from './authentication-extensions-inputs.model';
import { AuthenticatorSelectionCriteria } from './authenticator-selection-criteria.model';
import { PublicKeyCredentialDescriptor } from './public-key-credential-descriptor.model';
import { PublicKeyCredentialParameters } from './public-key-credential-parameters.model';
import { PublicKeyCredentialRpEntity } from './public-key-credential-rp-entity.model';
import { PublicKeyCredentialUser } from './public-key-credential-user.model';
import { Base64UrlString, attestationConveyancePreferenceValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class BiometricRegistrationOptions implements PublicKeyCredentialCreationOptionsJSON {
    @property({
        type: PublicKeyCredentialRpEntity,
        required: true
    })
    rp: PublicKeyCredentialRpEntity;

    @property({
        type: PublicKeyCredentialUser,
        required: true
    })
    user: PublicKeyCredentialUser;

    @property({
        type: 'string',
        required: true
    })
    challenge: Base64UrlString;

    @property({
        type: 'array',
        itemType: 'object',
        required: false,
        jsonSchema: getJsonSchema(PublicKeyCredentialParameters)
    })
    pubKeyCredParams: PublicKeyCredentialParameters[];

    @property({
        type: 'number',
        required: false
    })
    timeout?: number;

    @property({
        type: 'array',
        itemType: 'object',
        required: false,
        jsonSchema: getJsonSchema(PublicKeyCredentialDescriptor)
    })
    excludeCredentials?: PublicKeyCredentialDescriptor[];

    @property({
        type: AuthenticatorSelectionCriteria,
        required: false
    })
    authenticatorSelection?: AuthenticatorSelectionCriteria;

    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: attestationConveyancePreferenceValues
        }
    })
    attestation?: AttestationConveyancePreference;

    @property({
        type: AuthenticationExtensionsInputs,
        required: false
    })
    extensions?: AuthenticationExtensionsInputs;
}