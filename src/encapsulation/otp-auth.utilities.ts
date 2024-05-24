import { Secret, TOTP } from 'otpauth';

/**
 * TOTP: Time-Based One-Time Password Algorithm.
 * @see — RFC 6238
 */
export type OtpTOTP = TOTP;

/**
 * OTP secret key.
 */
export type OtpSecret = Secret;

/**
 * Options for creating a new TOTP object.
 */
export type OtpTOTPCreateOptions = {
    /**
     * Account provider.
     */
    issuer?: string,
    /**
     * Account label.
     */
    label?: string,
    /**
     * Secret key.
     */
    secret?: string | Secret,
    /**
     * HMAC hashing algorithm.
     */
    algorithm?: string,
    /**
     * Token length.
     */
    digits?: number,
    /**
     * Token time-step duration.
     */
    period?: number
};

/**
 * Options for generation a TOTP Token.
 */
export type OtpTOTPGenerateOptions = {
    /**
     * Secret key.
     */
    secret: Secret,
    /**
     * HMAC hashing algorithm.
     */
    algorithm?: string,
    /**
     * Token length.
     */
    digits?: number,
    /**
     * Token time-step duration.
     */
    period?: number,
    /**
     * Timestamp value in milliseconds.
     */
    timestamp?: number
};

/**
 * Encapsulates functionality of the otpauth package.
 */
export abstract class OtpAuthUtilities {
    /**
     * Creates a TOTP object.
     * @param options - Options for generating the TOTP.
     * @returns A TOTP (Time based One Time Password).
     */
    static createTOTP(options: OtpTOTPCreateOptions): OtpTOTP {
        return new TOTP(options);
    }

    /**
     * Generates a TOTP token.
     * @param options - Configuration options.
     * @returns — Token.
     */
    static generate(options: OtpTOTPGenerateOptions): string {
        return TOTP.generate(options);
    }

    /**
     * Converts a base32 string to a Secret object.
     * @param value - Base32 string.
     * @returns Secret object.
     */
    static secretFromBase32(value: string): OtpSecret {
        return Secret.fromBase32(value);
    }
}