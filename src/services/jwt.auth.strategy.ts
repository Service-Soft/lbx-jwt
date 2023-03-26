import { AuthenticationStrategy, TokenService } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { HttpErrors, Request } from '@loopback/rest';
import { UserProfile } from '@loopback/security';
import { LbxJwtBindings } from '../keys';

/**
 * The jwt authentication strategy.
 */
export class JwtAuthenticationStrategy implements AuthenticationStrategy {

    // eslint-disable-next-line jsdoc/require-jsdoc
    readonly name: string = 'jwt';

    constructor(
        @inject(LbxJwtBindings.ACCESS_TOKEN_SERVICE)
        private readonly accessTokenService: TokenService
    ) {}

    // eslint-disable-next-line jsdoc/require-jsdoc
    async authenticate(request: Request): Promise<UserProfile | undefined> {
        const token: string = this.extractTokenFromRequest(request);
        const userProfile: UserProfile = await this.accessTokenService.verifyToken(token);
        return userProfile;
    }

    /**
     * Extracts the token from the given request.
     *
     * @param request - The request to get the token from.
     * @returns The found token. An error otherwise.
     * @throws An Http-Unauthorized-Error when no token could be found.
     */
    extractTokenFromRequest(request: Request): string {
        if (!request.headers.authorization) {
            throw new HttpErrors.Unauthorized('Authorization header not found.');
        }

        // for example : Bearer xxx.yyy.zzz
        const authHeaderValue: string = request.headers.authorization;

        if (!authHeaderValue.startsWith('Bearer')) {
            throw new HttpErrors.Unauthorized(
                'Authorization header is not of type \'Bearer\'.'
            );
        }

        //split the string into 2 parts : 'Bearer ' and the `xxx.yyy.zzz`
        const parts: string[] = authHeaderValue.split(' ');
        if (parts.length !== 2) {
            throw new HttpErrors.Unauthorized(
                // eslint-disable-next-line max-len
                'Authorization header value has too many parts. It must follow the pattern: \'Bearer xx.yy.zz\' where xx.yy.zz is a valid JWT token.'
            );
        }

        const token: string = parts[1];
        return token;
    }
}