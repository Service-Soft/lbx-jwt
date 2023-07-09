import { authenticate } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { IsolationLevel, juggler } from '@loopback/repository';
import { HttpErrors, Request, RestBindings, getModelSchemaRef, post, requestBody } from '@loopback/rest';
import { SecurityBindings } from '@loopback/security';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { EncodedJwt, JwtUtilities } from '../../encapsulation/jwt.utilities';
import { LbxJwtBindings } from '../../keys';
import { BaseUser, BaseUserProfile, BaseUserWithRelations, Credentials, PasswordResetTokenWithRelations } from '../../models';
import { BaseUserRepository, CredentialsRepository, PasswordResetTokenRepository, RefreshTokenRepository } from '../../repositories';
import { AccessTokenService, BaseUserService, RefreshTokenService } from '../../services';
import { TwoFactorService } from '../../services/two-factor.service';
import { DefaultEntityOmitKeys, TokenObject } from '../../types';
import { AuthData } from './auth-data.model';
import { ConfirmResetPassword } from './confirm-reset-password.model';
import { LoginCredentials } from './login-credentials.model';
import { RefreshGrant } from './refresh-grant.model';
import { RequestResetPasswordGrant } from './request-reset-password-grant.model';
import { ResetPasswordTokenGrant } from './reset-password-token-grant.model';

/**
 * Exposes endpoints regarding authentication and authorization (eg. Login or resetting a users password).
 */
export class LbxJwtAuthController<RoleType extends string> {
    constructor(
        @inject(LbxJwtBindings.ACCESS_TOKEN_SERVICE)
        private readonly accessTokenService: AccessTokenService<RoleType>,
        @inject(LbxJwtBindings.ACCESS_TOKEN_SECRET)
        private readonly accessTokenSecret: string,
        @inject(LbxJwtBindings.BASE_USER_SERVICE)
        private readonly baseUserService: BaseUserService<RoleType>,
        @inject(LbxJwtBindings.REFRESH_TOKEN_SERVICE)
        private readonly refreshTokenService: RefreshTokenService<RoleType>,
        @inject(LbxJwtBindings.PASSWORD_RESET_TOKEN_REPOSITORY)
        private readonly passwordResetTokenRepository: PasswordResetTokenRepository<RoleType>,
        @inject(LbxJwtBindings.BASE_USER_REPOSITORY)
        private readonly baseUserRepository: BaseUserRepository<RoleType>,
        @inject(LbxJwtBindings.CREDENTIALS_REPOSITORY)
        private readonly credentialsRepository: CredentialsRepository,
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        private readonly dataSource: juggler.DataSource,
        @inject(LbxJwtBindings.ACCESS_TOKEN_EXPIRES_IN_MS)
        private readonly accessTokenExpiresInMs: number,
        @inject(LbxJwtBindings.REFRESH_TOKEN_EXPIRES_IN_MS)
        private readonly refreshTokenExpiresInMs: number,
        @inject(LbxJwtBindings.REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: RefreshTokenRepository,
        @inject(LbxJwtBindings.TWO_FACTOR_SERVICE)
        private readonly twoFactorService: TwoFactorService<RoleType>,
        @inject(LbxJwtBindings.TWO_FACTOR_HEADER)
        protected readonly twoFactorHeader: string
    ) {}

    /**
     * Tries to login a user with the provided email and password.
     *
     * @param loginCredentials - Contains the email and password of a user.
     * @param request - The injected request object. Is needed to access the two factor code inside a custom header.
     * @returns Auth Data for the user including the jwt.
     */
    @post(
        'login',
        {
            responses: {
                '200': {
                    description: 'Auth Data for the user including the access and refresh token',
                    content: {
                        'application/json': {
                            schema: getModelSchemaRef(AuthData)
                        }
                    }
                }
            }
        }
    )
    async login(
        @requestBody({
            required: true,
            content: {
                'application/json': {
                    schema: getModelSchemaRef(LoginCredentials)
                }
            }
        })
        loginCredentials: LoginCredentials,
        @inject(RestBindings.Http.REQUEST)
        request: Request
    ): Promise<Omit<AuthData<RoleType>, DefaultEntityOmitKeys> | { require2fa: boolean }> {
        const user: BaseUser<RoleType> = await this.baseUserService.verifyCredentials(loginCredentials);
        if (user.twoFactorEnabled == true) {
            if (!request.rawHeaders.find(h => h === this.twoFactorHeader)) {
                return {
                    require2fa: true
                };
            }
            await this.twoFactorService.validateCode(user.id, this.twoFactorService.extractCodeFromRequest(request));
        }
        const userProfile: BaseUserProfile<RoleType> = this.baseUserService.convertToUserProfile(user);
        const accessToken: string = await this.accessTokenService.generateToken(userProfile);
        const refreshTokenObject: TokenObject = await this.refreshTokenService.generateToken(userProfile, accessToken);
        return {
            accessToken: {
                value: refreshTokenObject.accessToken,
                expirationDate: new Date(Date.now() + this.accessTokenExpiresInMs)
            },
            refreshToken: {
                value: refreshTokenObject.refreshToken,
                expirationDate: new Date(Date.now() + this.refreshTokenExpiresInMs)
            },
            roles: user.roles,
            twoFactorEnabled: user.twoFactorEnabled ?? false,
            userId: user.id
        };
    }

    /**
     * Refreshes a token.
     *
     * @param refreshGrant - The refresh token send by the user.
     * @returns Auth Data for the user including the jwt.
     */
    @post(
        'refresh-token',
        {
            responses: {
                '200': {
                    description: 'Auth Data for the user including the access and refresh token',
                    content: {
                        'application/json': {
                            schema: getModelSchemaRef(AuthData)
                        }
                    }
                }
            }
        }
    )
    async refreshToken(
        @requestBody({
            required: true,
            content: {
                'application/json': {
                    schema: getModelSchemaRef(RefreshGrant)
                }
            }
        })
        refreshGrant: RefreshGrant
    ): Promise<Omit<AuthData<RoleType>, DefaultEntityOmitKeys>> {
        const refreshTokenObject: TokenObject = await this.refreshTokenService.refreshToken(refreshGrant.refreshToken);
        const encodedJwt: EncodedJwt<RoleType> = await JwtUtilities.verifyAsync(refreshTokenObject.accessToken, this.accessTokenSecret);
        const user: BaseUser<string> = await this.baseUserRepository.findById(encodedJwt.payload.id);
        return {
            accessToken: {
                value: refreshTokenObject.accessToken,
                expirationDate: new Date(Date.now() + this.accessTokenExpiresInMs)
            },
            refreshToken: {
                value: refreshTokenObject.refreshToken,
                expirationDate: new Date(Date.now() + this.refreshTokenExpiresInMs)
            },
            roles: encodedJwt.payload.roles,
            twoFactorEnabled: user.twoFactorEnabled ?? false,
            userId: encodedJwt.payload.id
        };
    }

    /**
     * Logout a user. Cleans up all existing refresh tokens of the current token family.
     *
     * @param refreshGrant - The refresh token of the user that should be logged out.
     */
    @post(
        'logout',
        {
            responses: {
                '200': {
                    description: 'Logout successful'
                }
            }
        }
    )
    async logout(
        @requestBody({
            required: true,
            content: {
                'application/json': {
                    schema: getModelSchemaRef(RefreshGrant)
                }
            }
        })
        refreshGrant: RefreshGrant
    ): Promise<void> {
        await this.refreshTokenService.revokeTokenFamily(refreshGrant.refreshToken);
    }

    /**
     * Requests the reset of a password.
     *
     * @param requestResetPassword - Contains the email of the user for which a password reset should be requested.
     */
    @post(
        'request-reset-password',
        {
            responses: {
                '200': {
                    description: 'ResetPassword Request successful'
                }
            }
        }
    )
    async requestResetPassword(
        @requestBody({
            required: true,
            content: {
                'application/json': {
                    schema: getModelSchemaRef(RequestResetPasswordGrant)
                }
            }
        })
        requestResetPassword: RequestResetPasswordGrant
    ): Promise<void> {
        await this.baseUserService.requestResetPassword(requestResetPassword);
    }

    /**
     * Verifies a given reset password token.
     * Throws an error if something is wrong with the token, does noting otherwise.
     *
     * @param token - The token that should be verified.
     */
    @post(
        'verify-password-reset-token',
        {
            responses: {
                '204': {
                    description: 'ResetToken Verify success'
                }
            }
        }
    )
    async verifyPasswordResetToken(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(ResetPasswordTokenGrant)
                }
            }
        })
        token: ResetPasswordTokenGrant
    ): Promise<void> {
        const resetToken: PasswordResetTokenWithRelations | null
            = await this.passwordResetTokenRepository.findOne({ where: { value: token.value } });
        if (!resetToken) {
            throw new HttpErrors.InternalServerError(`No password reset token found for ${token.value}`);
        }
        if (new Date(resetToken.expirationDate).getTime() <= Date.now()) {
            await this.passwordResetTokenRepository.deleteById(resetToken.id);
            throw new HttpErrors.Unauthorized('Link expired');
        }
        await this.baseUserRepository.findById(resetToken.baseUserId);
    }

    /**
     * Confirms the reset of the password and tries to set it to the given password.
     *
     * @param resetPasswordData - Contains the password reset token and the new password value.
     */
    @post(
        'confirm-reset-password',
        {
            responses: {
                '200': {
                    description: 'ResetPassword success'
                }
            }
        }
    )
    async confirmResetPassword(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(ConfirmResetPassword)
                }
            }
        })
        resetPasswordData: ConfirmResetPassword
    ): Promise<void> {
        const resetToken: PasswordResetTokenWithRelations | null
            = await this.passwordResetTokenRepository.findOne({ where: { value: resetPasswordData.resetToken } });
        if (!resetToken) {
            throw new HttpErrors.InternalServerError(`No password reset token found for ${resetPasswordData.resetToken}`);
        }
        if (new Date(resetToken.expirationDate).getTime() <= Date.now()) {
            await this.passwordResetTokenRepository.deleteById(resetToken.id);
            throw new HttpErrors.Unauthorized('Link expired');
        }

        const user: BaseUserWithRelations<RoleType> = await this.baseUserRepository.findById(resetToken.baseUserId);
        const credentials: Credentials = await this.baseUserRepository.credentials(user.id).get();
        const hashedPassword: string = await BcryptUtilities.hash(resetPasswordData.password);
        credentials.password = hashedPassword;

        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            await this.credentialsRepository.updateById(credentials.id, credentials, { transaction: transaction });
            await this.passwordResetTokenRepository.deleteById(resetToken.id, { transaction: transaction });
            await this.refreshTokenRepository.deleteAll({ baseUserId: resetToken.baseUserId }, { transaction: transaction });
            await transaction.commit();
        }
        catch (error) {
            await transaction.rollback();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            throw new HttpErrors.InternalServerError(`Error trying to set a new password: ${error.message}`);
        }
    }

    /**
     * Generates a two factor secret for the requesting user and returns a qr code url to display.
     *
     * @param userProfile - The currently logged in user.
     * @returns A qr code url for the user.
     */
    @authenticate('jwt')
    @post(
        '/2fa/turn-on',
        {
            responses: {
                '200': {
                    description: 'Success'
                }
            }
        }
    )
    async turnOn2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<string>
    ): Promise<{url: string}> {
        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            const qrCodeUrl: string = await this.twoFactorService.turnOn2FA(userProfile.id, { transaction: transaction });
            await transaction.commit();
            return { url: qrCodeUrl };
        }
        catch (error) {
            await transaction.rollback();
            throw error;
        }
    }

    /**
     * Confirms turning on the two factor authentication by checking the provided code.
     *
     * @param userProfile - The currently logged in user.
     * @param request - The injected request object. Is needed to access the two factor code inside a custom header.
     */
    @authenticate('jwt')
    @post(
        '/2fa/confirm-turn-on',
        {
            responses: {
                '200': {
                    description: 'Success'
                }
            }
        }
    )
    async confirmTurnOn2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<string>,
        @inject(RestBindings.Http.REQUEST)
        request: Request
    ): Promise<void> {
        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            const code: string = this.twoFactorService.extractCodeFromRequest(request);
            await this.twoFactorService.confirmTurnOn2FA(userProfile.id, code, { transaction: transaction });
            await transaction.commit();
        }
        catch (error) {
            await transaction.rollback();
            throw error;
        }
    }

    /**
     * Turns off two factor authentication for the current user.
     *
     * @param userProfile - The currently logged in user.
     */
    @authenticate('jwt')
    @post(
        '/2fa/turn-off',
        {
            responses: {
                '200': {
                    description: 'Success'
                }
            }
        }
    )
    async turnOff2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<string>
    ): Promise<void> {
        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            await this.twoFactorService.turnOff2FA(userProfile.id, { transaction: transaction });
            await transaction.commit();
        }
        catch (error) {
            await transaction.rollback();
            throw error;
        }
    }
}