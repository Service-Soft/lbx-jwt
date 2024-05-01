import { Getter } from '@loopback/core';
import { expect } from '@loopback/testlab';
import { Secret, TOTP } from 'otpauth';

import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { BaseUser, Credentials } from '../../models';
import { BaseUserRepository, CredentialsRepository } from '../../repositories';
import { TwoFactorService } from '../../services';
import { DefaultEntityOmitKeys } from '../../types';
import { testDb } from '../fixtures/test-db.datasource';

const credentialsRepository: CredentialsRepository = new CredentialsRepository(testDb);
const credentialsRepositoryGetter: Getter<CredentialsRepository> = async () => credentialsRepository;
const baseUserRepository: BaseUserRepository<string> = new BaseUserRepository(testDb, credentialsRepositoryGetter);

const twoFactorService: TwoFactorService<string> = new TwoFactorService(false, baseUserRepository, 'X-Authorization-2FA');

let user: BaseUser<string>;
describe('TwoFactorService', () => {
    before(async () => {
        user = await baseUserRepository.create({ email: 'user@example.com', roles: ['user'] });
        const credentials: Omit<Credentials, DefaultEntityOmitKeys | 'id' | 'baseUserId'> = {
            password: await BcryptUtilities.hash('42')
        };
        const finishedCredentials: Credentials = await baseUserRepository.credentials(user.id).create(credentials);
        expect(finishedCredentials.twoFactorAuthUrl).to.be.undefined();
        expect(finishedCredentials.twoFactorSecret).to.be.undefined();
        expect(user.twoFactorEnabled).to.be.undefined();
    });
    it('turnOn2FA', async () => {
        await twoFactorService.turnOn2FA(user.id);
        const credentials: Credentials = await baseUserRepository.credentials(user.id).get();
        expect(credentials.twoFactorAuthUrl).to.not.be.undefined();
        expect(credentials.twoFactorSecret).to.not.be.undefined();
        expect((await baseUserRepository.findById(user.id)).twoFactorEnabled).to.be.undefined();
    });

    it('confirmTurnOn2FA', async () => {
        const credentials: Credentials = await baseUserRepository.credentials(user.id).get();
        const code: string = TOTP.generate({ secret: Secret.fromBase32(credentials.twoFactorSecret as string) });
        await twoFactorService.confirmTurnOn2FA(user.id, code);
        expect((await baseUserRepository.findById(user.id)).twoFactorEnabled).to.be.true();
    });

    it('turnOff2FA', async () => {
        await twoFactorService.turnOff2FA(user.id);

        let credentials: Credentials = await baseUserRepository.credentials(user.id).get();
        expect(credentials.twoFactorAuthUrl).to.be.undefined();
        expect(credentials.twoFactorSecret).to.be.undefined();

        user = await baseUserRepository.findById(user.id);
        expect(user.twoFactorEnabled).to.be.false();

        await twoFactorService.turnOn2FA(user.id);
        credentials = await baseUserRepository.credentials(user.id).get();
        const code: string = TOTP.generate({ secret: Secret.fromBase32(credentials.twoFactorSecret as string) });
        await twoFactorService.confirmTurnOn2FA(user.id, code);
    });

    it('extractCodeFromRequest', () => {
        // const request: Request =
        // twoFactorService.extractCodeFromRequest(user.id);
    });

    it('validateCode', async () => {
        const credentials: Credentials = await baseUserRepository.credentials(user.id).get();
        const correctCode: string = TOTP.generate({ secret: Secret.fromBase32(credentials.twoFactorSecret as string) });

        await expect(twoFactorService.validateCode(user.id, correctCode)).to.not.be.rejected();

        await expect(twoFactorService.validateCode(user.id, '123456')).to.be.rejected();
    });
});