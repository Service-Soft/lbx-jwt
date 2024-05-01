import { randomBytes } from 'crypto';

import { DefaultHasOneRepository, HasOneRepository, juggler } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';
import { SinonSpy, StubbedInstanceWithSinonAccessor, createStubInstance, expect, sinon } from '@loopback/testlab';
import { Transporter } from 'nodemailer';

import { RequestResetPasswordGrant } from '../../controllers/auth/request-reset-password-grant.model';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { BaseUser, BaseUserProfile, Credentials, PasswordResetToken } from '../../models';
import { BaseUserRepository, CredentialsRepository, PasswordResetTokenRepository } from '../../repositories';
import { BaseMailService, BaseUserService } from '../../services';
import { DefaultEntityOmitKeys } from '../../types';


enum Roles {
    USER = 'user',
    ADMIN = 'admin'
}

const testDb: StubbedInstanceWithSinonAccessor<juggler.DataSource> = createStubInstance(juggler.DataSource);
const transaction: juggler.Transaction = {
    commit: async () => {
        return;
    },
    rollback: async () => {
        return;
    }
};
testDb.stubs.beginTransaction.resolves(transaction);


class MailService extends BaseMailService<string> {

    protected readonly WEBSERVER_MAIL: string = 'webserver@test.com';

    protected readonly BASE_RESET_PASSWORD_LINK: string = 'http://localhost:4200/reset-password';

    protected readonly webserverMailTransporter: Transporter;

    protected readonly PRODUCTION: boolean = false;

    protected readonly SAVED_EMAILS_PATH: string = './test-emails';

    protected override readonly LOGO_HEADER_URL: string = 'https://via.placeholder.com/165x165';

    protected override readonly LOGO_FOOTER_URL: string = 'https://via.placeholder.com/500x60';

    protected readonly ADDRESS_LINES: string[] = ['my address', 'my name'];
}


const baseUserRepository: StubbedInstanceWithSinonAccessor<BaseUserRepository<Roles>> = createStubInstance(BaseUserRepository) as StubbedInstanceWithSinonAccessor<BaseUserRepository<Roles>>;
const credentialsRepository: StubbedInstanceWithSinonAccessor<CredentialsRepository> = createStubInstance(CredentialsRepository);

const passwordResetTokenRepository: StubbedInstanceWithSinonAccessor<PasswordResetTokenRepository<Roles>> = createStubInstance(PasswordResetTokenRepository);
const mailService: MailService = new MailService();

const baseUserService: BaseUserService<Roles> = new BaseUserService<Roles>(baseUserRepository, passwordResetTokenRepository, 300000, testDb, mailService);

describe('BaseUserService', () => {
    it('verifyCredentials', async () => {
        const createBaseUserResult: BaseUser<Roles> = {
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER],
            roleValues: Object.values(Roles),
            getId: () => '1',
            getIdObject: () => '1',
            toJSON: () => '',
            toObject: () => {
                return {};
            },
            credentials: {
                id: '1',
                password: 'hashedPw',
                baseUserId: '1',
                getId: () => '1',
                getIdObject: () => '1',
                toJSON: () => '',
                toObject: () => {
                    return {};
                }
            }
        } as unknown as BaseUser<Roles>;
        baseUserRepository.stubs.create.resolves(createBaseUserResult);
        const user: BaseUser<Roles> = await baseUserRepository.create({
            email: 'user@example.com',
            roles: [Roles.USER]
        });

        const createCredentialsResult: Credentials = {
            id: '1',
            password: await BcryptUtilities.hash('password'),
            baseUserId: '1',
            getId: () => '1',
            getIdObject: () => '1',
            toJSON: () => '',
            toObject: () => {
                return {};
            }
        };
        credentialsRepository.stubs.create.resolves(createCredentialsResult);
        const credentials: Credentials = await credentialsRepository.create({
            password: await BcryptUtilities.hash('password'),
            baseUserId: user.id
        });

        baseUserRepository.stubs.findOne.resolves(user);

        const credentialsHasOneRepository: StubbedInstanceWithSinonAccessor<HasOneRepository<Credentials>> = createStubInstance(DefaultHasOneRepository);
        credentialsHasOneRepository.stubs.get.resolves(credentials);
        (baseUserRepository.stubs.credentials as unknown) = () => credentialsHasOneRepository;
        const userFromVerifiedCredentials: BaseUser<Roles> = await baseUserService.verifyCredentials({
            email: 'user@example.com',
            password: 'password',
            toJSON: () => '',
            toObject: () => {
                return {};
            }
        });

        expect(user).to.equal(userFromVerifiedCredentials);

        const expectedError: HttpErrors.HttpError<401> = new HttpErrors.Unauthorized('Invalid email or password.');
        await expect(
            baseUserService.verifyCredentials({
                email: 'user@example.com',
                password: 'invalidPassword',
                toJSON: () => '',
                toObject: () => {
                    return {};
                }
            })
        ).to.be.rejectedWith(expectedError);
    });

    it('convertToUserProfile', () => {
        const user: Omit<BaseUser<Roles>, DefaultEntityOmitKeys | 'credentials'> = {
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        const userProfile: BaseUserProfile<Roles> = baseUserService.convertToUserProfile(user as BaseUser<Roles>);
        expect(userProfile).to.eql({
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        });
    });

    it('requestResetPassword', async () => {
        const mailSpy: SinonSpy = sinon.spy(mailService, 'sendResetPasswordMail');
        const user: Omit<BaseUser<Roles>, DefaultEntityOmitKeys | 'credentials'> = {
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        baseUserRepository.stubs.findOne.resolves(user as BaseUser<Roles>);
        const createPasswordResetTokenResult: Omit<PasswordResetToken, DefaultEntityOmitKeys> = {
            id: '1',
            expirationDate: new Date(Date.now() + 300000),
            baseUserId: '1',
            value: randomBytes(16).toString('hex')
        };
        passwordResetTokenRepository.stubs.create.resolves(createPasswordResetTokenResult as PasswordResetToken);
        await baseUserService.requestResetPassword({ email: 'user@example.com' } as RequestResetPasswordGrant);
        sinon.assert.calledOnceWithExactly(mailSpy, user, createPasswordResetTokenResult);
    });
});