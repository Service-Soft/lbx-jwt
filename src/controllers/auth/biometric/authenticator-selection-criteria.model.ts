//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';
import { AuthenticatorSelectionCriteria as AuthenticatorSelectionCriteriaInterface } from '@simplewebauthn/types';

import { authenticatorAttachmentValues, requirementValues } from '../../../encapsulation/webauthn.utilities';

@model()
export class AuthenticatorSelectionCriteria implements AuthenticatorSelectionCriteriaInterface {
    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: authenticatorAttachmentValues
        }
    })
    authenticatorAttachment?: AuthenticatorAttachment;

    @property({
        type: 'boolean',
        required: false
    })
    requireResidentKey?: boolean;

    @property({
        type: 'string',
        required: false,
        jsonSchema: {
            enum: requirementValues
        }
    })
    residentKey?: ResidentKeyRequirement;

    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: requirementValues
        }
    })
    userVerification?: UserVerificationRequirement;
}