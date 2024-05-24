//TODO: Remove
/* eslint-disable jsdoc/require-jsdoc */
import { model, property } from '@loopback/repository';

import { DevicePublicKeyAuthenticatorOutput } from './device-public-key-authenticator-output.model';
import { UvmAuthenticatorOutput } from './uvm-authenticator-output.model';

@model()
export class AuthenticatorExtensionsAuthenticatorOutputs {
    @property({
        type: DevicePublicKeyAuthenticatorOutput,
        required: false
    })
    devicePubKey?: DevicePublicKeyAuthenticatorOutput;

    @property({
        type: UvmAuthenticatorOutput,
        required: false
    })
    uvm?: UvmAuthenticatorOutput;
}