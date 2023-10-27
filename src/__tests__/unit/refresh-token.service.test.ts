import { juggler } from '@loopback/repository';
import { securityId } from '@loopback/security';
import { createStubInstance, expect, sinon, StubbedInstanceWithSinonAccessor } from '@loopback/testlab';
import { Transporter } from 'nodemailer';
import { BaseUser, BaseUserProfile, RefreshTokenWithRelations } from '../../models';
import { BaseUserRepository, PasswordResetTokenRepository, RefreshTokenRepository } from '../../repositories';
import { AccessTokenService, BaseMailService, BaseUserService, RefreshTokenService } from '../../services';
import { DefaultEntityOmitKeys, TokenObject } from '../../types';
import { sleep } from '../fixtures/helpers';


enum Roles {
    USER = 'user',
    ADMIN = 'admin'
}


class MailService extends BaseMailService<Roles> {

    protected readonly WEBSERVER_MAIL: string = 'webserver@test.com';

    protected readonly BASE_RESET_PASSWORD_LINK: string = 'http://localhost:4200/reset-password';

    protected readonly webserverMailTransporter: Transporter;

    protected readonly PRODUCTION: boolean = false;

    protected readonly SAVED_EMAILS_PATH: string = './test-emails';

    protected override readonly LOGO_HEADER_URL: string = 'https://via.placeholder.com/165x165';

    protected override readonly LOGO_FOOTER_URL: string = 'https://via.placeholder.com/500x60';

    protected readonly ADDRESS_LINES: string[] = ['my address', 'my name'];
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


const baseUserRepository: StubbedInstanceWithSinonAccessor<BaseUserRepository<Roles>> = createStubInstance(BaseUserRepository) as StubbedInstanceWithSinonAccessor<BaseUserRepository<Roles>>;

const passwordResetTokenRepository: StubbedInstanceWithSinonAccessor<PasswordResetTokenRepository<Roles>> = createStubInstance(PasswordResetTokenRepository);
const refreshTokenRepository: StubbedInstanceWithSinonAccessor<RefreshTokenRepository> = createStubInstance(RefreshTokenRepository);
const mailService: MailService = new MailService();

const userService: BaseUserService<Roles> = new BaseUserService<Roles>(baseUserRepository, passwordResetTokenRepository, 300000, testDb, mailService);
const accessTokenService: AccessTokenService<Roles> = new AccessTokenService('accessSecret', 3600000);

const refreshTokenService: RefreshTokenService<Roles> = new RefreshTokenService<Roles>(
    'refreshSecret',
    8640000000,
    'api',
    baseUserRepository,
    refreshTokenRepository,
    userService,
    accessTokenService,
    testDb,
    3600000
);

describe('RefreshTokenService', () => {
    it('generateToken', async () => {
        const userProfile: BaseUserProfile<Roles> = {
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        const accessTokenValue: string = await accessTokenService.generateToken(userProfile);
        await refreshTokenService.generateToken(userProfile, accessTokenValue);
        sinon.assert.calledOnce(refreshTokenRepository.stubs.create);
    });

    it('refreshToken', async () => {
        const userProfile: BaseUserProfile<Roles> = {
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        const oldAccessTokenValue: string = await accessTokenService.generateToken(userProfile);
        const oldRefreshTokenValue: string = (await refreshTokenService.generateToken(userProfile, oldAccessTokenValue)).refreshToken;
        await sleep(1000);
        const findRefreshTokenResult: Omit<RefreshTokenWithRelations, DefaultEntityOmitKeys> = {
            id: '1',
            baseUserId: '1',
            tokenValue: 'jwt-refresh-token',
            familyId: '1',
            blacklisted: false,
            expirationDate: new Date(Date.now() + 8640000000)
        };
        const user: Omit<BaseUser<Roles>, DefaultEntityOmitKeys | 'credentials'> = {
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };

        refreshTokenRepository.stubs.findOne.resolves(findRefreshTokenResult as RefreshTokenWithRelations);
        baseUserRepository.stubs.findById.resolves(user as BaseUser<Roles>);

        const newTokenObject: TokenObject = await refreshTokenService.refreshToken(oldRefreshTokenValue);

        expect(newTokenObject.accessToken).to.not.eql(oldAccessTokenValue);
        expect(newTokenObject.refreshToken).to.eql(oldRefreshTokenValue);

        findRefreshTokenResult.expirationDate = new Date(Date.now());
        await sleep(500);
        refreshTokenRepository.stubs.findOne.resolves(findRefreshTokenResult as RefreshTokenWithRelations);

        const newTokenObjectTwo: TokenObject = await refreshTokenService.refreshToken(oldRefreshTokenValue);

        expect(newTokenObjectTwo.accessToken).to.not.eql(oldAccessTokenValue);
        expect(newTokenObjectTwo.refreshToken).to.not.eql(oldRefreshTokenValue);
    });

    it('verifyToken', async () => {
        const userProfile: BaseUserProfile<Roles> = {
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        const accessTokenValue: string = await accessTokenService.generateToken(userProfile);
        const refreshTokenValue: string = (await refreshTokenService.generateToken(userProfile, accessTokenValue)).refreshToken;
        const findTokenResult: Omit<RefreshTokenWithRelations, DefaultEntityOmitKeys> = {
            id: '1',
            baseUserId: '1',
            tokenValue: 'jwt-refresh-token',
            familyId: '1',
            blacklisted: false,
            expirationDate: new Date(Date.now() + 8640000000)
        };
        refreshTokenRepository.stubs.findOne.resolves(findTokenResult as RefreshTokenWithRelations);

        const refreshToken: RefreshTokenWithRelations = await refreshTokenService.verifyToken(refreshTokenValue);

        sinon.assert.calledWithExactly(refreshTokenRepository.stubs.findOne, { where: { tokenValue: refreshTokenValue } });
        expect(refreshToken).to.eql(findTokenResult);
    });

    it('revokeToken', async () => {
        const userProfile: BaseUserProfile<Roles> = {
            [securityId]: '1',
            id: '1',
            email: 'user@example.com',
            roles: [Roles.USER]
        };
        const accessTokenValue: string = await accessTokenService.generateToken(userProfile);
        const refreshTokenValue: string = (await refreshTokenService.generateToken(userProfile, accessTokenValue)).refreshToken;
        const findTokenResult: Omit<RefreshTokenWithRelations, DefaultEntityOmitKeys> = {
            id: '1',
            baseUserId: '1',
            tokenValue: 'jwt-refresh-token',
            familyId: '1',
            blacklisted: false,
            expirationDate: new Date(Date.now() + 8640000000)
        };
        refreshTokenRepository.stubs.findOne.resolves(findTokenResult as RefreshTokenWithRelations);

        await refreshTokenService.revokeTokenFamily(refreshTokenValue);
        sinon.assert.calledWithExactly(refreshTokenRepository.stubs.findOne, { where: { tokenValue: refreshTokenValue } });
        sinon.assert.calledWithExactly(refreshTokenRepository.stubs.deleteAll, { familyId: '1' });
    });
});