/* eslint-disable jsdoc/require-hyphen-before-param-description */
import { model, property } from '@loopback/repository';

import { RegistrationInfo } from './registration-info.model';

/**
 * Result of registration verification.
 * @param verified - If the assertion response could be verified.
 * @param registrationInfo.fmt - Type of attestation.
 * @param registrationInfo.counter - The number of times the authenticator reported it has been used.
 * **Should be kept in a DB for later reference to help prevent replay attacks!**.
 * @param registrationInfo.aaguid - Authenticator's Attestation GUID indicating the type of the
 * authenticator.
 * @param registrationInfo.credentialPublicKey The credential's public key.
 * @param registrationInfo.credentialID The credential's credential ID for the public key above.
 * @param registrationInfo.credentialType The type of the credential returned by the browser.
 * @param registrationInfo.userVerified Whether the user was uniquely identified during attestation.
 * @param registrationInfo.attestationObject The raw `response.attestationObject` Buffer returned by
 * the authenticator.
 * @param registrationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**.
 * @param registrationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**.
 * @param registrationInfo.origin The origin of the website that the registration occurred on.
 * @param registrationInfo?.rpID The RP ID that the registration occurred on, if one or more were
 * specified in the registration options.
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser.
 */
@model()
export class VerifiedBiometricRegistration {
    /**
     * If the assertion response could be verified.
     */
    @property({
        type: 'boolean',
        required: true
    })
    verified: boolean;
    /**
     * Information about the registration.
     */
    @property({
        type: RegistrationInfo,
        required: false
    })
    registrationInfo?: RegistrationInfo;
}