import { sign, verify, Secret, SignOptions, JwtHeader } from 'jsonwebtoken';

import { JwtPayload } from '../models/jwt.model';

/**
 * An encoded token.
 */
export interface EncodedJwt<RoleType extends string> {
    /**
     * The header of the jwt, contains mostly metadata.
     */
    header: JwtHeader,
    /**
     * The payload of the jwt, everything that was put inside the token when generating it can be found here.
     */
    payload: JwtPayload<RoleType>,
    /**
     * The signature of the jwt.
     */
    signature: string
}

/**
 * Encapsulates functionality of the jsonwebtoken package.
 */
export abstract class JwtUtilities {
    /**
     * Asynchronously sign the given payload into a JSON Web Token string payload.
     * @param payload - Any info that should be put inside the token.
     * @param secret - The secret used to encrypt the token.
     * @param options - Additional options like "expiresIn".
     * @returns A promise of the jwt.
     */
    static async signAsync(
        payload: string | Buffer | object,
        secret: Secret,
        options?: SignOptions
    ): Promise<string> {
        return new Promise((resolve, reject) => {
            try {
                const jwtValue: string = sign(payload, secret, options);
                resolve(jwtValue);
            }
            catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Asynchronously verify given token using a secret or a public key to get a decoded token.
     * @param token - The token to encode.
     * @param secret - The secret to encode the token with.
     * @returns The encoded token.
     */
    static async verifyAsync<RoleType extends string>(
        token: string,
        secret: Secret
    ): Promise<EncodedJwt<RoleType>> {
        return new Promise((resolve, reject) => {
            try {
                const jwt: EncodedJwt<RoleType> = verify(token, secret, { complete: true }) as EncodedJwt<RoleType>;
                resolve(jwt);
            }
            catch (error) {
                reject(error);
            }
        });
    }
}