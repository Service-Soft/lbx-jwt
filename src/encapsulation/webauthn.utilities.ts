/* eslint-disable jsdoc/check-param-names */
import base64 from '@hexagon/base64';
import { GenerateAuthenticationOptionsOpts, GenerateRegistrationOptionsOpts, VerifiedAuthenticationResponse as SWAVerifiedAuthenticationResponse, VerifiedRegistrationResponse, VerifyAuthenticationResponseOpts, VerifyRegistrationResponseOpts, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';

// eslint-disable-next-line jsdoc/require-jsdoc
type ConditionalType<InputType, ReturnType> =
    InputType extends undefined
        ? undefined
        : ReturnType;

/**
 * The values for AuthenticatorTransport property definitions.
 */
export const authenticatorTransportFutureValues: string[] = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'];

/**
 * The values for AuthenticatorAttachment property definitions.
 */
export const authenticatorAttachmentValues: string[] = ['cross-platform', 'platform'];

/**
 * The values for Requirement property definitions.
 */
export const requirementValues: string[] = ['discouraged', 'preferred', 'required'];

/**
 * The values for AttestationConveyancePreference property definitions.
 */
export const attestationConveyancePreferenceValues: string[] = ['none', 'direct', 'enterprise', 'indirect'];

/**
 * The values for PublicKeyCredentialType property definitions.
 */
export const publicKeyCredentialTypeValues: string[] = ['public-key'];

/**
 * The values for AttestationFormat property definitions.
 */
// eslint-disable-next-line cspell/spellchecker
export const attestationFormatValues: string[] = ['none', 'fido-u2f', 'packed', 'android-safetynet', 'android-key', 'tpm', 'apple'];

/**
 * The possible AttestationFormats.
 */
export type AttestationFormat = typeof attestationFormatValues[number];

/**
 * The values for CredentialDeviceType property definitions.
 */
export const credentialDeviceTypeValues: string[] = ['singleDevice', 'multiDevice'];

/**
 * The type of the credential device used.
 */
export type CredentialDeviceType = typeof credentialDeviceTypeValues[number];

/**
 * Verified authentication response. Comes from the frontend when biometric authentication was successful.
 */
export type VerifiedAuthenticationResponse = SWAVerifiedAuthenticationResponse;

/**
 * Helper type for the base64 string.
 */
// eslint-disable-next-line jsdoc/require-jsdoc
type Opaque<T, K extends string> = T & { __typename: K };

/**
 * Type for a base64 string. This does not apply any type checking and is just programmatic sugar.
 */
export type Base64UrlString = Opaque<string, 'base64'>;

/**
 * Encapsulates functionality of the **@simplewebauthn/server** package.
 */
export abstract class WebauthnUtilities {
    // eslint-disable-next-line jsdoc/require-param, jsdoc/require-returns
    /**
     * Prepare a value to pass into navigator.credentials.create(...) for authenticator registration.
     *
     * **Options:**.
     * @param rpName - User-visible, "friendly" website/service name.
     * @param rpID - Valid domain name (after `https://`).
     * @param userName - User's website-specific username (email, etc...).
     * @param userID - **(Optional)** - User's website-specific unique ID. Defaults to generating a random identifier.
     * @param challenge - **(Optional)** - Random value the authenticator needs to sign and pass back. Defaults to generating a random value.
     * @param userDisplayName - **(Optional)** - User's actual name. Defaults to `""`.
     * @param timeout - **(Optional)** - How long (in ms) the user can take to complete attestation. Defaults to `60000`.
     * @param attestationType - **(Optional)** - Specific attestation statement. Defaults to `"none"`.
     * @param excludeCredentials - **(Optional)** - Authenticators registered by the user so the user can't register the same credential multiple times. Defaults to `[]`.
     * @param authenticatorSelection - **(Optional)** - Advanced criteria for restricting the types of authenticators that may be used. Defaults to `{ residentKey: 'preferred', userVerification: 'preferred' }`.
     * @param extensions - **(Optional)** - Additional plugins the authenticator or browser should use during attestation.
     * @param supportedAlgorithmIDs - **(Optional)** - Array of numeric COSE algorithm identifiers supported for attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms. Defaults to `[-8, -7, -257]`.
     */
    static async generateRegistrationOptions(options: GenerateRegistrationOptionsOpts): Promise<PublicKeyCredentialCreationOptionsJSON> {
        return generateRegistrationOptions(options);
    }

    // eslint-disable-next-line jsdoc/require-param, jsdoc/require-returns
    /**
     * Verify that the user has legitimately completed the registration process.
     *
     * **Options:**.
     * @param response - Response returned by **@simplewebauthn/browser**'s `startAuthentication()`.
     * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateRegistrationOptions()`.
     * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on.
     * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options.
     * @param expectedType - **(Optional)** - The response type expected ('webauthn.create').
     * @param requireUserVerification - **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`.
     * @param supportedAlgorithmIDs - **(Optional)** - Array of numeric COSE algorithm identifiers supported for attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms. Defaults to all supported algorithm IDs.
     */
    static async verifyRegistrationResponse(options: VerifyRegistrationResponseOpts): Promise<VerifiedRegistrationResponse> {
        return verifyRegistrationResponse(options);
    }

    // eslint-disable-next-line jsdoc/require-param, jsdoc/require-returns
    /**
     * Prepare a value to pass into navigator.credentials.get(...) for authenticator authentication.
     *
     * **Options:**.
     * @param rpID - Valid domain name (after `https://`).
     * @param allowCredentials - **(Optional)** - Authenticators previously registered by the user, if any. If undefined the client will ask the user which credential they want to use.
     * @param challenge - **(Optional)** - Random value the authenticator needs to sign and pass back user for authentication. Defaults to generating a random value.
     * @param timeout - **(Optional)** - How long (in ms) the user can take to complete authentication. Defaults to `60000`.
     * @param userVerification - **(Optional)** - Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise set to `'preferred'` or `'required'` as desired. Defaults to `"preferred"`.
     * @param extensions - **(Optional)** - Additional plugins the authenticator or browser should use during authentication.
     */
    static async generateAuthenticationOptions(options: GenerateAuthenticationOptionsOpts): Promise<PublicKeyCredentialRequestOptionsJSON> {
        return generateAuthenticationOptions(options);
    }

    // eslint-disable-next-line jsdoc/require-param, jsdoc/require-returns
    /**
     * Verify that the user has legitimately completed the authentication process.
     *
     * **Options:**.
     * @param response - Response returned by **@simplewebauthn/browser**'s `startAssertion()`.
     * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateAuthenticationOptions()`.
     * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on.
     * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options.
     * @param authenticator - An internal AuthenticatorDevice matching the credential's ID.
     * @param expectedType - **(Optional)** - The response type expected ('webauthn.get').
     * @param requireUserVerification - **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`.
     * @param advancedFIDOConfig - **(Optional)** - Options for satisfying more stringent FIDO RP feature requirements.
     * @param advancedFIDOConfig.userVerification - **(Optional)** - Enable alternative rules for evaluating the User Presence and User Verified flags in authenticator data: UV (and UP) flags are optional unless this value is `"required"`.
     */
    static async verifyAuthenticationResponse(options: VerifyAuthenticationResponseOpts): Promise<VerifiedAuthenticationResponse> {
        return verifyAuthenticationResponse(options);
    }

    /**
     * Converts the given Uint8Array to a base64 url string.
     * @param value - The value to convert.
     * @returns A Base64UrlString that forces you to assign the value with "as string".
     */
    static uint8ToBase64UrlString<T extends Uint8Array | undefined>(value: T): ConditionalType<T, Base64UrlString> {
        if (value == undefined) {
            return undefined as ConditionalType<T, Base64UrlString>;
        }
        return base64.fromArrayBuffer(value, true) as ConditionalType<T, Base64UrlString>;
    }

    /**
     * Converts the given Base64UrlString to a Uint8Array.
     * @param value - The value to convert.
     * @returns The respective Uint8Array.
     */
    static base64UrlStringToUint8(value: Base64UrlString): Uint8Array {
        const normalString: string = base64.toString(value, true);
        return new TextEncoder().encode(normalString);
    }
}