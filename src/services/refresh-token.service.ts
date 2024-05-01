import { generateUniqueId, inject } from '@loopback/core';
import { Options, juggler } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';

import { AccessTokenService } from './access-token.service';
import { BaseUserService } from './base-user.service';
import { convertMsToSeconds } from './convert-ms-to-seconds.function';
import { JwtUtilities } from '../encapsulation/jwt.utilities';
import { LbxJwtBindings } from '../keys';
import { BaseUser, RefreshToken, RefreshTokenWithRelations } from '../models';
import { BaseUserProfile } from '../models/base-user-profile.model';
import { BaseUserRepository, RefreshTokenRepository } from '../repositories';
import { DefaultEntityOmitKeys, TokenObject } from '../types';

/**
 * The info stored inside an auth token.
 */
interface RefreshTokenPayload {
    /**
     * A uuid generated for the token.
     */
    tokenId: string,
    /**
     * The id of the user that this refresh token belongs to.
     */
    baseUserId: string
}

/**
 * Handles refreshing of auth tokens.
 */
export class RefreshTokenService<RoleType extends string> {
    constructor(
        @inject(LbxJwtBindings.REFRESH_TOKEN_SECRET)
        private readonly refreshTokenSecret: string,
        @inject(LbxJwtBindings.REFRESH_TOKEN_EXPIRES_IN_MS)
        private readonly refreshTokenExpiresInMs: number,
        @inject(LbxJwtBindings.REFRESH_TOKEN_ISSUER)
        private readonly refreshIssuer: string,
        @inject(LbxJwtBindings.BASE_USER_REPOSITORY)
        private readonly baseUserRepository: BaseUserRepository<RoleType>,
        @inject(LbxJwtBindings.REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: RefreshTokenRepository,
        @inject(LbxJwtBindings.BASE_USER_SERVICE)
        private readonly userService: BaseUserService<RoleType>,
        @inject(LbxJwtBindings.ACCESS_TOKEN_SERVICE)
        private readonly accessTokenService: AccessTokenService<RoleType>,
        @inject(LbxJwtBindings.REFRESH_TOKEN_DATASOURCE_KEY)
        private readonly dataSource: juggler.DataSource,
        @inject(LbxJwtBindings.ACCESS_TOKEN_EXPIRES_IN_MS)
        private readonly accessTokenExpiresInMs: number
    ) {}

    /**
     * Generate a refresh token, bind it with the given user profile, then store them in backend.
     * @param userProfile - The user profile for which the token should be generated.
     * @param token - The access token of the user.
     * @returns An object containing the access and the refresh token.
     */
    async generateToken(userProfile: BaseUserProfile<RoleType>, token: string): Promise<TokenObject> {
        const payload: RefreshTokenPayload = {
            baseUserId: userProfile[securityId],
            tokenId: generateUniqueId()
        };
        const refreshTokenValue: string = await JwtUtilities.signAsync(payload, this.refreshTokenSecret, {
            expiresIn: convertMsToSeconds(this.refreshTokenExpiresInMs),
            issuer: 'api'
        });
        const refreshToken: Omit<RefreshToken, DefaultEntityOmitKeys | 'id'> = {
            baseUserId: userProfile[securityId],
            tokenValue: refreshTokenValue,
            familyId: generateUniqueId(),
            blacklisted: false,
            expirationDate: new Date(Date.now() + this.refreshTokenExpiresInMs)
        };
        await this.refreshTokenRepository.create(refreshToken);
        return {
            accessToken: token,
            refreshToken: refreshTokenValue
        };
    }

    /**
     * Refresh the access token bound with the given refresh token.
     * @param refreshTokenValue - The refresh token value used to refresh the token.
     * @param options - Additional options eg. Transaction.
     * @returns An object containing the new access and the new refresh token.
     */
    async refreshToken(refreshTokenValue: string, options?: Options): Promise<TokenObject> {
        const refreshToken: RefreshTokenWithRelations = await this.verifyToken(refreshTokenValue, options);
        if (refreshToken.blacklisted) {
            await this.refreshTokenRepository.deleteAll({ familyId: refreshToken.familyId });
            throw new HttpErrors.Unauthorized('The given refresh token has already been used.');
        }

        const user: BaseUser<RoleType> = await this.baseUserRepository.findById(refreshToken.baseUserId, undefined, options);
        const userProfile: BaseUserProfile<RoleType> = this.userService.convertToUserProfile(user);

        const newAccessTokenValue: string = await this.accessTokenService.generateToken(userProfile);
        if (!this.refreshTokenIsExpired(refreshToken)) {
            return {
                accessToken: newAccessTokenValue,
                refreshToken: refreshTokenValue
            };
        }

        const newRefreshTokenPayload: RefreshTokenPayload = {
            baseUserId: userProfile[securityId],
            tokenId: generateUniqueId()
        };
        const newRefreshTokenValue: string = await JwtUtilities.signAsync(newRefreshTokenPayload, this.refreshTokenSecret, {
            expiresIn: convertMsToSeconds(this.refreshTokenExpiresInMs),
            issuer: this.refreshIssuer
        });
        const refreshTokenData: Omit<RefreshToken, DefaultEntityOmitKeys | 'id'> = {
            baseUserId: userProfile[securityId],
            tokenValue: newRefreshTokenValue,
            familyId: refreshToken.familyId,
            blacklisted: false,
            expirationDate: new Date(Date.now() + this.refreshTokenExpiresInMs)
        };
        await this.refreshTokenRepository.create(refreshTokenData, options);
        await this.refreshTokenRepository.updateById(refreshToken.id, { blacklisted: true }, options);

        await this.refreshTokenRepository.deleteAll({ expirationDate: { lte: new Date() } }, options);

        return {
            accessToken: newAccessTokenValue,
            refreshToken: newRefreshTokenValue
        };
    }

    private refreshTokenIsExpired(refreshToken: RefreshTokenWithRelations): boolean {
        const createdAt: Date = new Date(new Date(refreshToken.expirationDate).getTime() - this.refreshTokenExpiresInMs);
        const accessTokenLifeTimeInMs: number = Date.now() - createdAt.getTime();
        return accessTokenLifeTimeInMs > this.accessTokenExpiresInMs;
    }

    /**
     * Revokes the family of the given token.
     * That means that every refresh token that comes from the same original login gets deleted.
     * @param refreshTokenValue - The value of the token that should be revoked.
     */
    async revokeTokenFamily(refreshTokenValue: string): Promise<void> {
        try {
            const refreshToken: RefreshTokenWithRelations | null
                = await this.refreshTokenRepository.findOne({ where: { tokenValue: refreshTokenValue } });
            if (!refreshToken) {
                return;
            }
            await this.refreshTokenRepository.deleteAll({ familyId: refreshToken.familyId });
        }
        catch (e) {
            // ignore
        }
    }

    /**
     * Verify the validity of a refresh token, and make sure it exists in backend.
     * @param refreshToken - The refresh token that should be verified.
     * @param options - Additional options eg. Transaction.
     * @returns The found refresh token with its relations or an error.
     */
    async verifyToken(refreshToken: string, options?: Options): Promise<RefreshTokenWithRelations> {
        try {
            await JwtUtilities.verifyAsync(refreshToken, this.refreshTokenSecret);
            const userRefreshData: RefreshTokenWithRelations | null = await this.refreshTokenRepository.findOne(
                { where: { tokenValue: refreshToken } },
                options
            );

            if (!userRefreshData) {
                throw new HttpErrors.Unauthorized('Error verifying token: Invalid Token');
            }
            return userRefreshData;
        }
        catch (error) {
            throw new HttpErrors.Unauthorized(
                // eslint-disable-next-line typescript/no-unsafe-member-access
                `Error verifying refresh token: ${error.message}`
            );
        }
    }
}