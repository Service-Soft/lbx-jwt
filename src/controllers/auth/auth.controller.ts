import { inject } from '@loopback/core';
import { getModelSchemaRef, HttpErrors, post, requestBody } from '@loopback/rest';
import { BaseUser, BaseUserProfile, BaseUserWithRelations, Credentials, PasswordResetTokenWithRelations } from '../../models';
import { authenticate } from '@loopback/authentication';
import { LbxJwtBindings } from '../../keys';
import { AccessTokenService, BaseUserService, RefreshTokenService } from '../../services';
import { LoginCredentials } from './login-credentials.model';
import { DefaultEntityOmitKeys, TokenObject } from '../../types';
import { EncodedJwt, JwtUtilities } from '../../encapsulation/jwt.utilities';
import { RequestResetPasswordGrant } from './request-reset-password-grant.model';
import { AuthData } from './auth-data.model';
import { RefreshGrant } from './refresh-grant.model';
import { IsolationLevel, juggler } from '@loopback/repository';
import { BaseUserRepository, CredentialsRepository, PasswordResetTokenRepository, RefreshTokenRepository } from '../../repositories';
import { ResetPasswordTokenGrant } from './reset-password-token-grant.model';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { ConfirmResetPassword } from './confirm-reset-password.model';

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
        private readonly refreshTokenRepository: RefreshTokenRepository
    ) {}

    /**
     * Tries to login a user with the provided email and password.
     *
     * @param loginCredentials - Contains the email and password of a user.
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
        loginCredentials: LoginCredentials
    ): Promise<Omit<AuthData<RoleType>, DefaultEntityOmitKeys>> {
        const user: BaseUser<RoleType> = await this.baseUserService.verifyCredentials(loginCredentials);
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
            userId: encodedJwt.payload.id
        };
    }

    /**
     * Logout a user. Cleans up all existing refresh tokens of the current token family.
     *
     * @param refreshGrant - The refresh token of the user that should be logged out.
     */
    @authenticate('jwt')
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
}