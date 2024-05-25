import { randomBytes } from 'crypto';

import { DefaultHasOneRepository, HasOneRepository, juggler } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';
import { SinonSpy, StubbedInstanceWithSinonAccessor, createStubInstance, expect, sinon } from '@loopback/testlab';

import { RequestResetPasswordGrant } from '../../controllers/auth/request-reset-password-grant.model';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { BaseUser, BaseUserProfile, Credentials, PasswordResetToken } from '../../models';
import { BaseUserRepository, CredentialsRepository, PasswordResetTokenRepository } from '../../repositories';
import { BaseUserService } from '../../services';
import { DefaultEntityOmitKeys } from '../../types';
import { testBiometricCredentialsService } from '../fixtures/biometric-credentials-service.fixture';
import { MailService } from '../fixtures/mail-service.fixture';
import { testBiometricCredentialsRepository } from '../fixtures/repositories.fixture';
import { TestRoles } from '../fixtures/roles.fixture';

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

const baseUserRepository: StubbedInstanceWithSinonAccessor<BaseUserRepository<TestRoles>> = createStubInstance(BaseUserRepository) as StubbedInstanceWithSinonAccessor<BaseUserRepository<TestRoles>>;
const credentialsRepository: StubbedInstanceWithSinonAccessor<CredentialsRepository> = createStubInstance(CredentialsRepository);

const passwordResetTokenRepository: StubbedInstanceWithSinonAccessor<PasswordResetTokenRepository<TestRoles>> = createStubInstance(PasswordResetTokenRepository);
const mailService: MailService = new MailService();

const baseUserService: BaseUserService<TestRoles> = new BaseUserService<TestRoles>(baseUserRepository, passwordResetTokenRepository, 300000, testDb, mailService, testBiometricCredentialsService, testBiometricCredentialsRepository);

describe('BaseUserService', () => {
    it('verifyCredentials', async () => {
        const createBaseUserResult: BaseUser<TestRoles> = {
            id: '1',
            // eslint-disable-next-line sonar/no-duplicate-string
            email: 'user@example.com',
            roles: [TestRoles.USER],
            roleValues: Object.values(TestRoles),
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
        } as unknown as BaseUser<TestRoles>;
        baseUserRepository.stubs.create.resolves(createBaseUserResult);
        const user: BaseUser<TestRoles> = await baseUserRepository.create({
            email: 'user@example.com',
            roles: [TestRoles.USER]
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
        const userFromVerifiedCredentials: BaseUser<TestRoles> = await baseUserService.verifyCredentials({
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
        const user: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials' | 'biometricCredentials'> = {
            id: '1',
            email: 'user@example.com',
            roles: [TestRoles.USER]
        };
        const userProfile: BaseUserProfile<TestRoles> = baseUserService.convertToUserProfile(user as BaseUser<TestRoles>);
        expect(userProfile).to.eql({
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [TestRoles.USER]
        });
    });

    it('requestResetPassword', async () => {
        const mailSpy: SinonSpy = sinon.spy(mailService, 'sendResetPasswordMail');
        const user: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials' | 'biometricCredentials'> = {
            id: '1',
            email: 'user@example.com',
            roles: [TestRoles.USER]
        };
        baseUserRepository.stubs.findOne.resolves(user as BaseUser<TestRoles>);
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