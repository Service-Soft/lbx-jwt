/* eslint-disable unicorn/no-null */
import { expect } from '@loopback/testlab';

import { OtpAuthUtilities } from '../../encapsulation/otp-auth.utilities';
import { BaseUser, Credentials } from '../../models';
import { TwoFactorService } from '../../services';
import { DefaultEntityOmitKeys } from '../../types';
import { clearDatabase, createExampleUser } from '../fixtures/helpers';
import { testUserRepository } from '../fixtures/repositories.fixture';
import { TestRoles } from '../fixtures/roles.fixture';

const twoFactorService: TwoFactorService<TestRoles> = new TwoFactorService(false, testUserRepository, 'X-Authorization-2FA');

let user: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials'>;
describe('TwoFactorService', () => {
    before(async () => {
        await clearDatabase();
        user = await createExampleUser();
        const credentials: Credentials = await testUserRepository.credentials(user.id).get();
        expect(credentials.twoFactorAuthUrl).to.be.oneOf(null, undefined);
        expect(credentials.twoFactorSecret).to.be.oneOf(null, undefined);
        expect(user.twoFactorEnabled).to.be.oneOf(null, undefined);
    });
    it('turnOn2FA', async () => {
        await twoFactorService.turnOn2FA(user.id);
        const credentials: Credentials = await testUserRepository.credentials(user.id).get();
        expect(credentials.twoFactorAuthUrl).to.not.be.oneOf(null, undefined);
        expect(credentials.twoFactorSecret).to.not.be.oneOf(null, undefined);
        expect((await testUserRepository.findById(user.id)).twoFactorEnabled).to.be.oneOf(null, undefined);
    });

    it('confirmTurnOn2FA', async () => {
        const credentials: Credentials = await testUserRepository.credentials(user.id).get();
        const code: string = OtpAuthUtilities.generate({ secret: OtpAuthUtilities.secretFromBase32(credentials.twoFactorSecret as string) });
        await twoFactorService.confirmTurnOn2FA(user.id, code);
        expect((await testUserRepository.findById(user.id)).twoFactorEnabled).to.be.true();
    });

    it('turnOff2FA', async () => {
        await twoFactorService.turnOff2FA(user.id);

        let credentials: Credentials = await testUserRepository.credentials(user.id).get();
        expect(credentials.twoFactorAuthUrl).to.be.oneOf(null, undefined);
        expect(credentials.twoFactorSecret).to.be.oneOf(null, undefined);

        user = await testUserRepository.findById(user.id);
        expect(user.twoFactorEnabled).to.be.false();

        await twoFactorService.turnOn2FA(user.id);
        credentials = await testUserRepository.credentials(user.id).get();
        const code: string = OtpAuthUtilities.generate({ secret: OtpAuthUtilities.secretFromBase32(credentials.twoFactorSecret as string) });
        await twoFactorService.confirmTurnOn2FA(user.id, code);
    });

    it('extractCodeFromRequest', () => {
        // const request: Request =
        // twoFactorService.extractCodeFromRequest(user.id);
    });

    it('validateCode', async () => {
        const credentials: Credentials = await testUserRepository.credentials(user.id).get();
        const correctCode: string = OtpAuthUtilities.generate({ secret: OtpAuthUtilities.secretFromBase32(credentials.twoFactorSecret as string) });

        await expect(twoFactorService.validateCode(user.id, correctCode)).to.not.be.rejected();

        await expect(twoFactorService.validateCode(user.id, '123456')).to.be.rejected();
    });
});