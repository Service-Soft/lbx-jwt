//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';

@model()
export class BiometricCredentialPropertiesOutput implements CredentialPropertiesOutput {
    @property({
        type: 'boolean',
        required: false
    })
    rk?: boolean;
}