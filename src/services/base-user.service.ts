import { randomBytes } from 'crypto';

import { UserService } from '@loopback/authentication';
import { inject } from '@loopback/core';
import { IsolationLevel, juggler } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';

import { BaseMailService } from './mail/base-mail.service';
import { LoginCredentials } from '../controllers/auth/login-credentials.model';
import { RequestResetPasswordGrant } from '../controllers/auth/request-reset-password-grant.model';
import { BcryptUtilities } from '../encapsulation/bcrypt.utilities';
import { LbxJwtBindings } from '../keys';
import { BaseUser, Credentials } from '../models';
import { BaseUserProfile } from '../models/base-user-profile.model';
import { PasswordResetToken, PasswordResetTokenWithRelations } from '../models/password-reset-token.model';
import { BaseUserRepository } from '../repositories';
import { PasswordResetTokenRepository } from '../repositories/password-reset-token.repository';
import { DefaultEntityOmitKeys } from '../types';

/**
 * The base user service used for authentication and authorization.
 */
export class BaseUserService<RoleType extends string> implements UserService<BaseUser<RoleType>, LoginCredentials> {

    private readonly INVALID_CREDENTIALS_ERROR_MESSAGE: string = 'Invalid email or password.';

    constructor(
        @inject(LbxJwtBindings.BASE_USER_REPOSITORY)
        private readonly userRepository: BaseUserRepository<RoleType>,
        @inject(LbxJwtBindings.PASSWORD_RESET_TOKEN_REPOSITORY)
        private readonly passwordResetTokenRepository: PasswordResetTokenRepository<RoleType>,
        @inject(LbxJwtBindings.PASSWORD_RESET_TOKEN_EXPIRES_IN_MS)
        private readonly passwordResetTokenExpiresInMs: number,
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        private readonly dataSource: juggler.DataSource,
        @inject(LbxJwtBindings.MAIL_SERVICE)
        private readonly mailService: BaseMailService<RoleType>
    ) {}

    // eslint-disable-next-line jsdoc/require-jsdoc
    async verifyCredentials(credentials: LoginCredentials): Promise<BaseUser<RoleType>> {
        const foundUser: BaseUser<RoleType> | null = await this.userRepository.findOne({ where: { email: credentials.email } });
        if (!foundUser) {
            throw new HttpErrors.Unauthorized(this.INVALID_CREDENTIALS_ERROR_MESSAGE);
        }

        const credentialsFound: Credentials = await this.userRepository.credentials(foundUser.id).get();
        const passwordMatched: boolean = await BcryptUtilities.compare(credentials.password, credentialsFound.password);
        if (!passwordMatched) {
            throw new HttpErrors.Unauthorized(this.INVALID_CREDENTIALS_ERROR_MESSAGE);
        }

        return foundUser;
    }

    // eslint-disable-next-line jsdoc/require-jsdoc
    convertToUserProfile(user: BaseUser<RoleType>): BaseUserProfile<RoleType> {
        return {
            [securityId]: user.id,
            id: user.id,
            email: user.email,
            roles: user.roles
        };
    }

    /**
     * Requests the reset of the password.
     * @param requestResetPassword - Contains the email of the user which password should be reset.
     */
    async requestResetPassword(requestResetPassword: RequestResetPasswordGrant): Promise<void> {
        const user: BaseUser<RoleType> | null = await this.userRepository.findOne({ where: { email: requestResetPassword.email } });
        if (!user) {
            throw new HttpErrors.NotFound(`No User with email ${requestResetPassword.email} found.`);
        }
        if (await this.activeResetLinkAlreadyExists(user)) {
            throw new HttpErrors.TooManyRequests('A reset link has already been requested for this account.');
        }

        const transaction: juggler.Transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            const resetTokenData: Omit<PasswordResetToken, DefaultEntityOmitKeys | 'id'> = {
                expirationDate: new Date(Date.now() + this.passwordResetTokenExpiresInMs),
                baseUserId: user.id,
                value: randomBytes(16).toString('hex')
            };
            const resetToken: PasswordResetTokenWithRelations = await this.passwordResetTokenRepository.create(
                resetTokenData,
                {
                    transaction: transaction
                }
            );

            await this.mailService.sendResetPasswordMail(user, resetToken);
            await transaction.commit();
        }
        catch (error) {
            await transaction.rollback();
            throw error;
        }
    }

    private async activeResetLinkAlreadyExists(user: BaseUser<RoleType>): Promise<boolean> {
        const existingToken: PasswordResetTokenWithRelations | null
            = await this.passwordResetTokenRepository.findOne({ where: { baseUserId: user.id } });
        if (existingToken) {
            if (new Date(existingToken.expirationDate).getTime() > Date.now()) {
                return true;
            }
            await this.passwordResetTokenRepository.deleteById(existingToken.id);
        }
        return false;
    }
}