import { AuthenticationBindings, AuthenticationMetadata, AuthenticationStrategy, TokenService } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { HttpErrors, Request } from '@loopback/rest';

import { TwoFactorService } from './two-factor.service';
import { LbxJwtBindings } from '../keys';
import { BaseUser, BaseUserProfile } from '../models';
import { BaseUserRepository } from '../repositories';

/**
 * The jwt authentication strategy.
 */
export class JwtAuthenticationStrategy implements AuthenticationStrategy {

    // eslint-disable-next-line jsdoc/require-jsdoc
    readonly name: string = 'jwt';

    constructor(
        @inject(LbxJwtBindings.ACCESS_TOKEN_SERVICE)
        private readonly accessTokenService: TokenService,
        @inject(AuthenticationBindings.METADATA)
        private readonly metadataArray: AuthenticationMetadata[],
        @inject(LbxJwtBindings.BASE_USER_REPOSITORY)
        private readonly baseUserRepository: BaseUserRepository<string>,
        @inject(LbxJwtBindings.FORCE_TWO_FACTOR)
        private readonly forceTwoFactor: boolean,
        @inject(LbxJwtBindings.FORCE_TWO_FACTOR_ALLOWED_ROUTES)
        private readonly forceTwoFactorAllowedRoutes: string[],
        @inject(LbxJwtBindings.TWO_FACTOR_SERVICE)
        private readonly twoFactorService: TwoFactorService<string>
    ) {}

    // eslint-disable-next-line jsdoc/require-jsdoc
    async authenticate(request: Request): Promise<BaseUserProfile<string> | undefined> {
        const token: string = this.extractTokenFromRequest(request);
        const userProfile: BaseUserProfile<string> = await this.accessTokenService.verifyToken(token) as BaseUserProfile<string>;
        const user: BaseUser<string> = await this.baseUserRepository.findById(userProfile.id);
        // eslint-disable-next-line typescript/strict-boolean-expressions
        if (user.requiresPasswordChange) {
            throw new HttpErrors.BadRequest('This account needs to change his password before it can access this route.');
        }
        await this.validate2FA(user, request);
        return userProfile;
    }

    /**
     * Checks if the request requires 2fa and validates accordingly.
     * @param user - The currently logged in user.
     * @param request - The request, is used to extract the two factor code from the custom header.
     */
    protected async validate2FA(user: BaseUser<string>, request: Request): Promise<void> {
        if (
            this.forceTwoFactor && user.twoFactorEnabled != true
            && !this.forceTwoFactorAllowedRoutes.find(r => request.url === r || new URL(request.url).pathname === r)
        ) {
            throw new HttpErrors.BadRequest('This account needs to setup two factor authentication before it can access this route.');
        }
        const metadata: AuthenticationMetadata | undefined = this.metadataArray.find(m => m.strategy === this.name);
        // eslint-disable-next-line typescript/strict-boolean-expressions
        if (!metadata?.options?.['require2fa']) {
            return;
        }
        // eslint-disable-next-line typescript/strict-boolean-expressions
        if (!this.forceTwoFactor && !user.twoFactorEnabled) {
            return;
        }
        const code: string = this.twoFactorService.extractCodeFromRequest(request);
        await this.twoFactorService.validateCode(user.id, code);
    }

    /**
     * Extracts the token from the given request.
     * @param request - The request to get the token from.
     * @returns The found token. An error otherwise.
     * @throws An Http-Unauthorized-Error when no token could be found.
     */
    protected extractTokenFromRequest(request: Request): string {
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
                'Authorization header value has too many parts. It must follow the pattern: \'Bearer xx.yy.zz\' where xx.yy.zz is a valid JWT token.'
            );
        }

        const token: string = parts[1];
        return token;
    }
}