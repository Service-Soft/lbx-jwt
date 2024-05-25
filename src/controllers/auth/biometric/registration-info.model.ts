import { model, property } from '@loopback/repository';

import { AuthenticatorExtensionsAuthenticatorOutputs } from './authenticator-extensions-authenticator-outputs.model';
import { AttestationFormat, Base64UrlString, CredentialDeviceType, attestationFormatValues, credentialDeviceTypeValues, publicKeyCredentialTypeValues } from '../../../encapsulation/webauthn.utilities';

/**
 * Information about the registration.
 */
@model()
export class RegistrationInfo {
    /**
     * Type of attestation.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: attestationFormatValues
        }
    })
    fmt: AttestationFormat;
    /**
     * The number of times the authenticator reported it has been used.
     * **Should be kept in a DB for later reference to help prevent replay attacks!**.
     */
    @property({
        type: 'number',
        required: true
    })
    counter: number;
    /**
     * Authenticator's Attestation GUID indicating the type of the
     * authenticator.
     */
    @property({
        type: 'string',
        required: true
    })
    aaguid: string;
    /**
     * The credential's credential ID for the public key above.
     */
    @property({
        type: 'string',
        required: true
    })
    credentialID: Base64UrlString;
    /**
     * The credential's public key as a base64 string.
     */
    @property({
        type: 'string',
        required: true
    })
    credentialPublicKey: Base64UrlString;
    /**
     * The type of the credential returned by the browser.
     */
    @property({
        itemType: 'string',
        required: true,
        jsonSchema: {
            items: {
                enum: publicKeyCredentialTypeValues
            }
        }
    })
    credentialType: PublicKeyCredentialType;
    /**
     * The `response.attestationObject` returned by the authenticator as a base64 string.
     */
    @property({
        type: 'string',
        required: true
    })
    attestationObject: Base64UrlString;
    /**
     * Whether the user was uniquely identified during attestation.
     */
    @property({
        type: 'boolean',
        required: true
    })
    userVerified: boolean;
    /**
     * Whether this is a single-device or multi-device
     * credential. **Should be kept in a DB for later reference!**.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            enum: credentialDeviceTypeValues
        }
    })
    credentialDeviceType: CredentialDeviceType;
    /**
     * Whether or not the multi-device credential has been
     * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
     * reference!**.
     */
    @property({
        type: 'boolean',
        required: true
    })
    credentialBackedUp: boolean;
    /**
     * The origin of the website that the registration occurred on.
     */
    @property({
        type: 'string',
        required: true
    })
    origin: string;
    /**
     * The RP ID that the registration occurred on, if one or more were
     * specified in the registration options.
     */
    @property({
        type: 'string',
        required: false
    })
    rpID?: string;
    /**
     * The authenticator extensions returned
     * by the browser.
     */
    @property({
        type: AuthenticatorExtensionsAuthenticatorOutputs,
        required: true
    })
    authenticatorExtensionResults?: AuthenticatorExtensionsAuthenticatorOutputs;
}