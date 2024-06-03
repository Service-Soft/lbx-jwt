import { HttpErrors } from '@loopback/rest';
import { VerifiedRegistrationResponse } from '@simplewebauthn/server';
import { AuthenticationExtensionsAuthenticatorOutputs } from '@simplewebauthn/server/script/helpers/decodeAuthenticatorExtensions';
import { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';

import { BiometricRegistrationOptions } from '../controllers';
import { AuthenticationResponse } from '../controllers/auth/biometric/authentication-response.model';
import { AuthenticatorExtensionsAuthenticatorOutputs } from '../controllers/auth/biometric/authenticator-extensions-authenticator-outputs.model';
import { BiometricRegistrationResponse } from '../controllers/auth/biometric/biometric-registration-response.model';
import { PublicKeyCredentialRequestOptions } from '../controllers/auth/biometric/public-key-credential-request-options.model';
import { VerifiedBiometricRegistration } from '../controllers/auth/biometric/verified-biometric-registration.model';
import { Base64UrlString, WebauthnUtilities, VerifiedAuthenticationResponse } from '../encapsulation/webauthn.utilities';
import { BiometricCredentials } from '../models';

/**
 * The base service for handling biometric credentials.
 */
export abstract class BaseBiometricCredentialsService {
    /**
     * Human-readable title for your frontend.
     */
    protected abstract readonly RP_NAME: string;

    /**
     * The domain of your frontend. Without https:// and without any trailing /.
     */
    protected abstract readonly RP_DOMAIN: string;

    /**
     * Error message to throw when no registration was found with the provided challenge for verifying the registration response.
     */
    // eslint-disable-next-line stylistic/max-len
    protected readonly NO_REGISTRATION_WITH_PROVIDED_CHALLENGE_FOUND_ERROR_MESSAGE: string = 'No registration with provided challenge found.';

    // eslint-disable-next-line jsdoc/require-returns
    /**
     * The complete origin of your frontend.
     * By default this returns https://${this.RP_DOMAIN}.
     */
    protected get RP_ORIGIN(): string {
        return `https://${this.RP_DOMAIN}`;
    }

    /**
     * Generate biometric registration options.
     * @param userEmail - The email of the user to generate the options for.
     * @param alreadyRegisteredCredentials - Any already registered credentials of the user to avoid duplication.
     * @returns The generated registration options.
     */
    async generateRegistrationOptions(
        userEmail: string,
        alreadyRegisteredCredentials: BiometricCredentials[]
    ): Promise<BiometricRegistrationOptions> {
        const res: PublicKeyCredentialCreationOptionsJSON = await WebauthnUtilities.generateRegistrationOptions({
            rpName: this.RP_NAME,
            rpID: this.RP_DOMAIN,
            userName: userEmail,
            // Prompt users for additional information about the authenticator.
            attestationType: 'none',
            // Prevent users from re-registering existing authenticators
            excludeCredentials: alreadyRegisteredCredentials.map(c => {
                return {
                    id: c.credentialId
                };
            }),
            authenticatorSelection: {
                // Defaults
                residentKey: 'preferred',
                userVerification: 'preferred'
            }
        });
        return {
            ...res,
            challenge: res.challenge as Base64UrlString,
            excludeCredentials: res.excludeCredentials?.map(ec => {
                return {
                    ...ec,
                    id: ec.id as Base64UrlString
                };
            })
        };
    }

    /**
     * Verifies a biometric registration.
     * @param body - The request body including the data to verify (challenge, etc.).
     * @param expectedChallenge - The expected challenge.
     * @returns The verified biometric registration response.
     */
    async verifyRegistrationResponse(
        body: BiometricRegistrationResponse,
        expectedChallenge?: string
    ): Promise<VerifiedBiometricRegistration> {
        if (!expectedChallenge) {
            throw new HttpErrors.BadRequest(this.NO_REGISTRATION_WITH_PROVIDED_CHALLENGE_FOUND_ERROR_MESSAGE);
        }
        const res: VerifiedRegistrationResponse = await WebauthnUtilities.verifyRegistrationResponse({
            response: body,
            expectedChallenge: expectedChallenge,
            expectedOrigin: this.RP_ORIGIN,
            expectedRPID: this.RP_DOMAIN
        });
        return {
            ...res,
            registrationInfo: res.registrationInfo == undefined
                ? undefined
                : {
                    ...res.registrationInfo,
                    credentialID: res.registrationInfo.credentialID as Base64UrlString,
                    credentialPublicKey: WebauthnUtilities.uint8ToBase64UrlString(res.registrationInfo.credentialPublicKey),
                    attestationObject: WebauthnUtilities.uint8ToBase64UrlString(res.registrationInfo.attestationObject),
                    authenticatorExtensionResults: res.registrationInfo.authenticatorExtensionResults == undefined
                        ? undefined
                        : this.transformAuthenticatorExtensionResults(res.registrationInfo.authenticatorExtensionResults)
                }
        };
    }

    /**
     * Transforms the given authenticatorExtensionResults to an easier to use structure that uses base64 url strings instead of Uint8Arrays.
     * @param authenticatorExtensionResults - The original extension results to transform.
     * @returns The transformed value.
     */
    protected transformAuthenticatorExtensionResults(
        authenticatorExtensionResults: AuthenticationExtensionsAuthenticatorOutputs
    ): AuthenticatorExtensionsAuthenticatorOutputs {
        return {
            ...authenticatorExtensionResults,
            devicePubKey: {
                ...authenticatorExtensionResults.devicePubKey,
                dpk: WebauthnUtilities.uint8ToBase64UrlString(authenticatorExtensionResults.devicePubKey?.dpk),
                nonce: WebauthnUtilities.uint8ToBase64UrlString(authenticatorExtensionResults.devicePubKey?.nonce),
                scope: WebauthnUtilities.uint8ToBase64UrlString(authenticatorExtensionResults.devicePubKey?.scope),
                aaguid: WebauthnUtilities.uint8ToBase64UrlString(authenticatorExtensionResults.devicePubKey?.aaguid)
            },
            uvm: authenticatorExtensionResults.uvm == undefined
                ? undefined
                : {
                    uvm: authenticatorExtensionResults.uvm.uvm == undefined
                        ? undefined
                        : authenticatorExtensionResults.uvm.uvm.map(u => WebauthnUtilities.uint8ToBase64UrlString(u))
                }
        };
    }

    /**
     * Generates authentication options from the provided biometric credentials.
     * @param credentialsOfUser - The credentials to generate the options for.
     * @returns The generated authentication options.
     */
    async generateAuthenticationOptions(credentialsOfUser: BiometricCredentials[]): Promise<PublicKeyCredentialRequestOptions> {
        const res: PublicKeyCredentialRequestOptionsJSON = await WebauthnUtilities.generateAuthenticationOptions({
            rpID: this.RP_DOMAIN,
            allowCredentials: credentialsOfUser
        });
        return {
            ...res,
            challenge: res.challenge as Base64UrlString,
            allowCredentials: res.allowCredentials?.map(c => {
                return {
                    ...c,
                    id: c.id as Base64UrlString
                };
            })
        };
    }

    /**
     * Verify that the user has legitimately completed the authentication process.
     * @param body - The response from the frontend.
     * @param biometricCredential - The biometric credential that the user tries to login with.
     * @returns The verified authentication response.
     */
    async verifyAuthenticationResponse(
        body: AuthenticationResponse,
        biometricCredential: BiometricCredentials
    ): Promise<VerifiedAuthenticationResponse> {
        return WebauthnUtilities.verifyAuthenticationResponse({
            response: body,
            expectedChallenge: biometricCredential.challenge,
            expectedOrigin: `https://${this.RP_DOMAIN}`,
            expectedRPID: this.RP_DOMAIN,
            authenticator: {
                credentialID: biometricCredential.credentialId,
                credentialPublicKey: WebauthnUtilities.base64UrlStringToUint8(biometricCredential.publicKey),
                counter: biometricCredential.counter
            }
        });
    }
}