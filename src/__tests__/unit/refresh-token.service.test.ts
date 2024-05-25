import { IsolationLevel, juggler } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { securityId } from '@loopback/security';
import { SinonSpy, expect, sinon } from '@loopback/testlab';

import { AuthData } from '../../controllers';
import { EncodedJwt, JwtUtilities } from '../../encapsulation/jwt.utilities';
import { BaseUser, BaseUserProfile, RefreshToken, RefreshTokenWithRelations } from '../../models';
import { DefaultEntityOmitKeys, TokenObject } from '../../types';
import { testDb } from '../fixtures/db.fixture';
import { clearDatabase, createExampleUser, sleep } from '../fixtures/helpers';
import { testRefreshTokenRepository, testUserRepository } from '../fixtures/repositories.fixture';
import { TestRoles } from '../fixtures/roles.fixture';
import { testAccessTokenService, testRefreshTokenService } from '../fixtures/services.fixture';

let exampleUser: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials'>;
let exampleUserProfile: BaseUserProfile<TestRoles>;

describe('RefreshTokenService', () => {
    before(async () => {
        await clearDatabase();
        exampleUser = await createExampleUser();
        exampleUserProfile = {
            [securityId]: exampleUser.id,
            id: exampleUser.id,
            email: exampleUser.email,
            roles: exampleUser.roles
        };
    });

    it('generateToken', async () => {
        const createSpy: SinonSpy = sinon.spy(testRefreshTokenRepository, 'create');
        const accessTokenValue: string = await testAccessTokenService.generateToken(exampleUserProfile);
        await testRefreshTokenService.generateToken(exampleUserProfile, accessTokenValue);
        sinon.assert.calledOnce(createSpy);
    });

    it('refreshToken', async () => {
        const oldAccessTokenValue: string = await testAccessTokenService.generateToken(exampleUserProfile);
        const oldRefreshTokenValue: string = (await testRefreshTokenService.generateToken(exampleUserProfile, oldAccessTokenValue)).refreshToken;

        // we need to wait so that the time part in the new access token is different.
        // (at least the seconds need to differ)
        await sleep(1000);

        const newTokenObject: TokenObject = await testRefreshTokenService.refreshToken(oldRefreshTokenValue);

        // access tokens are not stored on the server, therefore they should always be freshly generated.
        expect(newTokenObject.accessToken).to.not.eql(oldAccessTokenValue);
        // The refresh token is stored on the server. When the token is not expired it should be reused.
        expect(newTokenObject.refreshToken).to.eql(oldRefreshTokenValue);

        // make the refresh token expired
        const refreshToken: RefreshToken | null = await testRefreshTokenRepository.findOne({ where: { baseUserId: exampleUser.id } });
        if (!refreshToken) {
            throw new Error(`No refresh token found for user with id ${exampleUser.id}`);
        }
        await testRefreshTokenRepository.updateById(refreshToken.id, { expirationDate: new Date() });

        await sleep(1000);

        const newTokenObjectTwo: TokenObject = await testRefreshTokenService.refreshToken(oldRefreshTokenValue);

        expect(newTokenObjectTwo.accessToken).to.not.eql(oldAccessTokenValue);
        expect(newTokenObjectTwo.refreshToken).to.not.eql(oldRefreshTokenValue);
    }).timeout(5000);

    it('refreshToken with transactions', async () => {
        const promises: Promise<Omit<AuthData<TestRoles>, DefaultEntityOmitKeys>>[] = [];
        for (let i: number = 0; i < 100; i++) {
            promises.push(refreshTokenWithTransaction());
        }
        await Promise.all(promises);
    }).timeout(5000);

    it('verifyToken', async () => {
        const findOneSpy: SinonSpy = sinon.spy(testRefreshTokenRepository, 'findOne');
        const accessTokenValue: string = await testAccessTokenService.generateToken(exampleUserProfile);
        const refreshTokenValue: string = (await testRefreshTokenService.generateToken(exampleUserProfile, accessTokenValue)).refreshToken;

        const refreshToken: RefreshTokenWithRelations = await testRefreshTokenService.verifyToken(refreshTokenValue);

        sinon.assert.calledWithExactly(findOneSpy, { where: { tokenValue: refreshTokenValue } }, undefined);
        expect(refreshToken.baseUserId).to.eql(exampleUser.id);
        expect(refreshToken.blacklisted).to.eql(false);
        const expirationDate: Date = new Date(Date.now() + 8640000000);
        expect(refreshToken.expirationDate.getDate()).to.eql(expirationDate.getDate());
        expect(refreshToken.expirationDate.getHours()).to.eql(expirationDate.getHours());
        expect(refreshToken.expirationDate.getMinutes()).to.eql(expirationDate.getMinutes());

        const expectedError: HttpErrors.HttpError<401> = new HttpErrors.Unauthorized('Error verifying refresh token: invalid token');
        const invalidToken: string = 'aaa.bbb.ccc';
        await expect(testRefreshTokenService.verifyToken(invalidToken)).to.be.rejectedWith(expectedError);
        findOneSpy.restore();
    });

    it('revokeToken', async () => {
        const findOneSpy: SinonSpy = sinon.spy(testRefreshTokenRepository, 'findOne');
        const deleteAllSpy: SinonSpy = sinon.spy(testRefreshTokenRepository, 'deleteAll');
        const accessTokenValue: string = await testAccessTokenService.generateToken(exampleUserProfile);
        const refreshTokenValue: string = (await testRefreshTokenService.generateToken(exampleUserProfile, accessTokenValue)).refreshToken;
        await testRefreshTokenService.revokeTokenFamily(refreshTokenValue);
        sinon.assert.calledOnceWithExactly(findOneSpy, { where: { tokenValue: refreshTokenValue } });
        sinon.assert.calledOnce(deleteAllSpy);
        findOneSpy.restore();
    });
});

async function refreshTokenWithTransaction(): Promise<Omit<AuthData<TestRoles>, DefaultEntityOmitKeys>> {
    const tempAccessToken: string = await testAccessTokenService.generateToken(exampleUserProfile);
    const refreshGrantRefreshToken: string = (await testRefreshTokenService.generateToken(exampleUserProfile, tempAccessToken)).refreshToken;

    await sleep((Math.random() + 1) * 1000);

    const transaction: juggler.Transaction = await testDb.beginTransaction(IsolationLevel.READ_COMMITTED);
    try {
        const refreshTokenObject: TokenObject = await testRefreshTokenService.refreshToken(refreshGrantRefreshToken, { transaction: transaction });
        const encodedJwt: EncodedJwt<TestRoles> = await JwtUtilities.verifyAsync(refreshTokenObject.accessToken, testAccessTokenService['accessTokenSecret']);
        const user: BaseUser<string> = await testUserRepository.findById(encodedJwt.payload.id, { include: [{ relation: 'biometricCredentials' }] }, { transaction: transaction });
        await transaction.commit();
        return {
            accessToken: {
                value: refreshTokenObject.accessToken,
                expirationDate: new Date(Date.now() + testAccessTokenService['accessTokenExpiresInMs'])
            },
            refreshToken: {
                value: refreshTokenObject.refreshToken,
                expirationDate: new Date(Date.now() + testRefreshTokenService['refreshTokenExpiresInMs'])
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