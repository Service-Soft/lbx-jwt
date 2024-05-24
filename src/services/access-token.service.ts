import { TokenService } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';

import { convertMsToSeconds } from './convert-ms-to-seconds.function';
import { EncodedJwt, JwtUtilities } from '../encapsulation/jwt.utilities';
import { LbxJwtBindings } from '../keys';
import { BaseUserProfile } from '../models/base-user-profile.model';
import { JwtPayload } from '../models/jwt.model';

/**
 * Generates and verifies access tokens.
 */
export class AccessTokenService<RoleType extends string> implements TokenService {
    constructor(
        @inject(LbxJwtBindings.ACCESS_TOKEN_SECRET)
        private readonly accessTokenSecret: string,
        @inject(LbxJwtBindings.ACCESS_TOKEN_EXPIRES_IN_MS)
        private readonly accessTokenExpiresInMs: number
    ) {}

    // eslint-disable-next-line jsdoc/require-jsdoc
    async verifyToken(token: string): Promise<BaseUserProfile<RoleType>> {
        try {
            const decodedToken: EncodedJwt<RoleType> = await JwtUtilities.verifyAsync(token, this.accessTokenSecret);
            // don't copy over  token field 'iat' and 'exp', nor 'email' to user profile
            const userProfile: Omit<BaseUserProfile<RoleType>, 'email'> = Object.assign(
                {
                    [securityId]: decodedToken.payload.id,
                    name: ''
                },
                {
                    id: decodedToken.payload.id,
                    roles: decodedToken.payload.roles
                }
            );
            return userProfile as BaseUserProfile<RoleType>;
        }
        catch (error) {
            // eslint-disable-next-line typescript/no-unsafe-member-access
            throw new HttpErrors.Unauthorized(`Error verifying access token: ${error.message}`);
        }
    }

    // eslint-disable-next-line jsdoc/require-jsdoc
    async generateToken(userProfile: BaseUserProfile<RoleType>): Promise<string> {
        // eslint-disable-next-line jsdoc/require-jsdoc
        const jwtPayload: JwtPayload<RoleType> & { email: string } = {
            id: userProfile[securityId],
            email: userProfile.email,
            roles: userProfile.roles
        };
        // Generate a JSON Web Token
        try {
            return await JwtUtilities.signAsync(
                jwtPayload,
                this.accessTokenSecret,
                { expiresIn: convertMsToSeconds(this.accessTokenExpiresInMs) }
            );
        }
        catch (error) {
            // eslint-disable-next-line typescript/no-unsafe-member-access
            throw new HttpErrors.Unauthorized(`Error generating token: ${error.message}`);
        }
    }
}