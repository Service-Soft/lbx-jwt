import { authenticate } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { IsolationLevel, juggler, model, property } from '@loopback/repository';
import { HttpErrors, Request, RestBindings, del, get, getModelSchemaRef, param, post, requestBody } from '@loopback/rest';
import { SecurityBindings } from '@loopback/security';

import { Require2FAResponseModel } from './2fa/require-2fa-response.model';
import { TurnOn2FAResponse } from './2fa/turn-on-2fa-response.model';
import { AuthData } from './auth-data.model';
import { AuthenticationResponse } from './biometric/authentication-response.model';
import { BiometricRegistrationOptions } from './biometric/biometric-registration-options.model';
import { BiometricRegistrationResponse } from './biometric/biometric-registration-response.model';
import { ConfirmBiometricRegistrationResponse } from './biometric/confirm-biometric-registration-response.model';
import { PublicKeyCredentialRequestOptions } from './biometric/public-key-credential-request-options.model';
import { VerifiedBiometricRegistration } from './biometric/verified-biometric-registration.model';
import { ConfirmResetPassword } from './confirm-reset-password.model';
import { LoginCredentials } from './login-credentials.model';
import { RefreshGrant } from './refresh-grant.model';
import { RequestResetPasswordGrant } from './request-reset-password-grant.model';
import { RequirePasswordChangeResponseModel } from './require-password-change.model';
import { ResetPasswordTokenGrant } from './reset-password-token-grant.model';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { EncodedJwt, JwtUtilities } from '../../encapsulation/jwt.utilities';
import { Base64UrlString } from '../../encapsulation/webauthn.utilities';
import { LbxJwtBindings } from '../../keys';
import { BaseUser, BaseUserProfile, BaseUserWithRelations, BiometricCredentials, Credentials, PasswordResetTokenWithRelations } from '../../models';
import { BaseUserRepository, BiometricCredentialsRepository, CredentialsRepository, PasswordResetTokenRepository, RefreshTokenRepository } from '../../repositories';
import { AccessTokenService, BaseBiometricCredentialsService, BaseUserService, RefreshTokenService } from '../../services';
import { TwoFactorService } from '../../services/two-factor.service';
import { DefaultEntityOmitKeys, TokenObject } from '../../types';

@model()
class VerifyResetTokenResponse {
    @property({
        type: 'boolean',
        required: true
    })
    isValid: boolean;
}

const PENDING: string = 'PENDING';

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
        @inject(LbxJwtBindings.BIOMETRIC_CREDENTIALS_REPOSITORY)
        private readonly biometricCredentialsRepository: BiometricCredentialsRepository,
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
        private readonly twoFactorHeader: string,
        @inject(LbxJwtBindings.BIOMETRIC_CREDENTIALS_SERVICE)
        private readonly biometricCredentialsService: BaseBiometricCredentialsService
    ) { }

    /**
     * Tries to login a user with the provided email and password.
     * @param loginCredentials - Contains the email and password of a user.
     * @param request - The injected request object. Is needed to access the two factor code inside a custom header.
     * @returns Auth Data for the user including the jwt.
     */
    @post(
        'login',
        {
            responses: {
                200: {
                    description: 'Auth Data for the user including the access and refresh token',
                    content: {
                        'application/json': {
                            schema: getModelSchemaRef(AuthData)
                        }
                    }
                },
                202: {
                    description: 'Login was successful, but the user is required to change his password.',
                    content: {
                        'application/json': {
                            schema: getModelSchemaRef(RequirePasswordChangeResponseModel)
                        }
                    }
                },
                206: {
                    description: 'Requires 2 factor code.',
                    content: {
                        'application/json': {
                            schema: getModelSchemaRef(Require2FAResponseModel)
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
                    schema: {
                        oneOf: [
                            getModelSchemaRef(LoginCredentials),
                            getModelSchemaRef(AuthenticationResponse)
                        ]
                    }
                }
            }
        })
        loginCredentials: LoginCredentials | AuthenticationResponse,
        @inject(RestBindings.Http.REQUEST)
        request: Request
    ): Promise<Omit<AuthData<RoleType>, DefaultEntityOmitKeys> | Require2FAResponseModel | RequirePasswordChangeResponseModel> {
        const user: BaseUser<RoleType> = await this.baseUserService.verifyCredentials(loginCredentials);
        if (user.requiresPasswordChange == true) {
            return {
                requirePasswordChange: true
            };
        }
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
        const biometricCredentials: BiometricCredentials[] = await this.baseUserRepository.biometricCredentials(user.id).find();
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
            userId: user.id,
            biometricCredentials: biometricCredentials
        };
    }

    /**
     * Refreshes a token.
     * @param refreshGrant - The refresh token send by the user.
     * @returns Auth Data for the user including the jwt.
     */
    @post('refresh-token', {
        responses: {
            200: {
                description: 'Auth Data for the user including the access and refresh token',
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(AuthData)
                    }
                }
            }
        }
    })
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
        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            const refreshTokenObject: TokenObject = await this.refreshTokenService.refreshToken(
                refreshGrant.refreshToken,
                { transaction: transaction }
            );
            const encodedJwt: EncodedJwt<RoleType> = await JwtUtilities.verifyAsync(refreshTokenObject.accessToken, this.accessTokenSecret);
            const user: BaseUser<RoleType> = await this.baseUserRepository.findById(
                encodedJwt.payload.id,
                { include: [{ relation: 'biometricCredentials' }] },
                { transaction: transaction }
            );
            await transaction.commit();
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
                userId: encodedJwt.payload.id,
                biometricCredentials: user.biometricCredentials ?? []
            };
        }
        catch (error) {
            await transaction.rollback();
            // eslint-disable-next-line typescript/no-unsafe-member-access
            throw new HttpErrors.Unauthorized(`Error refreshing token: ${error.message}`);
        }
    }

    /**
     * Logout a user. Cleans up all existing refresh tokens of the current token family.
     * @param refreshGrant - The refresh token of the user that should be logged out.
     */
    @post('logout', {
        responses: {
            200: {
                description: 'Logout successful'
            }
        }
    })
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
     * @param requestResetPassword - Contains the email of the user for which a password reset should be requested.
     */
    @post('request-reset-password', {
        responses: {
            200: {
                description: 'ResetPassword Request successful'
            }
        }
    })
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
     * @param token - The token that should be verified.
     * @returns Whether or not the provided token is valid.
     */
    @post('verify-password-reset-token', {
        responses: {
            204: {
                description: 'ResetToken Verify success',
                content: getModelSchemaRef(VerifyResetTokenResponse)
            }
        }
    })
    async verifyPasswordResetToken(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(ResetPasswordTokenGrant)
                }
            }
        })
        token: ResetPasswordTokenGrant
    ): Promise<VerifyResetTokenResponse> {
        const resetToken: PasswordResetTokenWithRelations | null
            = await this.passwordResetTokenRepository.findOne({ where: { value: token.value } });
        if (!resetToken) {
            return {
                isValid: false
            };
        }
        if (new Date(resetToken.expirationDate).getTime() <= Date.now()) {
            await this.passwordResetTokenRepository.deleteById(resetToken.id);
            return {
                isValid: false
            };
        }
        const referencedUser: BaseUser<RoleType> | null = await this.baseUserRepository.findOne({ where: { id: resetToken.baseUserId } });
        return {
            isValid: !!referencedUser
        };
    }

    /**
     * Confirms the reset of the password and tries to set it to the given password.
     * @param resetPasswordData - Contains the password reset token and the new password value.
     */
    @post('confirm-reset-password', {
        responses: {
            200: {
                description: 'ResetPassword success'
            }
        }
    })
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
            await this.baseUserRepository.updateById(user.id, { requiresPasswordChange: false }, { transaction: transaction });
            await transaction.commit();
        }
        catch (error) {
            await transaction.rollback();
            // eslint-disable-next-line typescript/no-unsafe-member-access
            throw new HttpErrors.InternalServerError(`Error trying to set a new password: ${error.message}`);
        }
    }

    /**
     * Generates a two factor secret for the requesting user and returns a qr code url to display.
     * @param userProfile - The currently logged in user.
     * @returns A qr code url for the user.
     */
    @authenticate('jwt')
    @post('/2fa/turn-on', {
        responses: {
            200: {
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(TurnOn2FAResponse)
                    }
                }
            }
        }
    })
    async turnOn2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>
    ): Promise<TurnOn2FAResponse> {
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
     * @param userProfile - The currently logged in user.
     * @param request - The injected request object. Is needed to access the two factor code inside a custom header.
     */
    @authenticate('jwt')
    @post('/2fa/confirm-turn-on', {
        responses: {
            200: {
                description: 'Success'
            }
        }
    })
    async confirmTurnOn2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>,
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
     * @param userProfile - The currently logged in user.
     */
    @authenticate('jwt')
    @post('/2fa/turn-off', {
        responses: {
            200: {
                description: 'Success'
            }
        }
    })
    async turnOff2FA(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>
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

    @authenticate('jwt')
    @post('/biometric/register', {
        responses: {
            200: {
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(BiometricRegistrationOptions)
                    }
                }
            }
        }
    })
    async registerBiometricCredential(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>
    ): Promise<BiometricRegistrationOptions> {
        const baseUser: BaseUser<RoleType> = await this.baseUserRepository.findById(
            userProfile.id,
            { include: [{ relation: 'biometricCredentials' }] }
        );
        // TODO: Maybe move this to a cron job?
        await this.biometricCredentialsRepository.deleteAll({ baseUserId: baseUser.id, expirationDate: { lte: new Date() } });
        const options: BiometricRegistrationOptions = await this.biometricCredentialsService.generateRegistrationOptions(
            baseUser.email,
            baseUser.biometricCredentials ?? []
        );
        const credentials: Omit<BiometricCredentials, DefaultEntityOmitKeys | 'id' | 'baseUserId'> = {
            challenge: options.challenge,
            credentialId: PENDING as Base64UrlString,
            publicKey: PENDING as Base64UrlString,
            counter: 0,
            expirationDate: new Date(Date.now() + 8640000000)
        };
        await this.baseUserRepository.biometricCredentials(baseUser.id).create(credentials);
        return options;
    }

    @authenticate('jwt')
    @del('/biometric/cancel-register/{challenge}', {
        responses: {
            200: {
                description: 'Success'
            }
        }
    })
    async cancelBiometricRegistration(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>,
        @param.path.string('challenge')
        challenge: string
    ): Promise<void> {
        await this.baseUserRepository.biometricCredentials(userProfile.id).delete({
            challenge: challenge as Base64UrlString,
            counter: 0,
            credentialId: PENDING as Base64UrlString,
            publicKey: PENDING as Base64UrlString
        });
    }

    @authenticate('jwt')
    @post('/biometric/confirm-register/{challenge}', {
        responses: {
            200: {
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(ConfirmBiometricRegistrationResponse)
                    }
                }
            }
        }
    })
    async confirmRegisterBiometricCredentials(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<RoleType>,
        @requestBody({
            required: true,
            content: {
                'application/json': {
                    schema: getModelSchemaRef(BiometricRegistrationResponse)
                }
            }
        })
        body: BiometricRegistrationResponse,
        @param.path.string('challenge')
        challenge: string
    ): Promise<ConfirmBiometricRegistrationResponse> {
        const baseUser: BaseUser<RoleType> = await this.baseUserRepository.findById(
            userProfile.id,
            { include: [{ relation: 'biometricCredentials' }] }
        );
        const existingBiometricCredential: BiometricCredentials | undefined = baseUser.biometricCredentials?.find(bc => {
            return bc.challenge === challenge
                && bc.credentialId === PENDING
                && bc.counter === 0
                && bc.publicKey === PENDING;
        });
        const res: VerifiedBiometricRegistration = await this.biometricCredentialsService.verifyRegistrationResponse(
            body,
            existingBiometricCredential?.challenge
        );
        if (res.verified && existingBiometricCredential) {
            await this.biometricCredentialsRepository.updateById(existingBiometricCredential.id, {
                credentialId: res.registrationInfo?.credentialID,
                publicKey: res.registrationInfo?.credentialPublicKey,
                counter: res.registrationInfo?.counter,
                expirationDate: undefined
            });
        }
        const biometricCredentials: BiometricCredentials[] = await this.baseUserRepository.biometricCredentials(baseUser.id).find();
        return {
            biometricCredentials: biometricCredentials,
            verified: res.verified
        };
    }

    @get('/biometric/authentication-options/{userId}', {
        responses: {
            200: {
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(PublicKeyCredentialRequestOptions)
                    }
                }
            }
        }
    })
    async generateAuthenticationOptions(
        @param.path.string('userId')
        userId: string
    ): Promise<PublicKeyCredentialRequestOptions> {
        const user: BaseUser<RoleType> = await this.baseUserRepository.findById(
            userId,
            { include: [{ relation: 'biometricCredentials' }] }
        );
        const options: PublicKeyCredentialRequestOptions = await this.biometricCredentialsService.generateAuthenticationOptions(
            user.biometricCredentials ?? []
        );
        await this.baseUserRepository.biometricCredentials(user.id).patch({ challenge: options.challenge });
        return options;
    }
}