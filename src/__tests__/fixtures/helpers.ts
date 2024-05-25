/* eslint-disable cspell/spellchecker */
import { IsolationLevel, juggler } from '@loopback/repository';
import { expect } from '@loopback/testlab';

import { testBiometricCredentialsService } from './biometric-credentials-service.fixture';
import { testDb } from './db.fixture';
import { testUserRepository, testCredentialsRepository, testPasswordResetTokenRepository, testRefreshTokenRepository, testBiometricCredentialsRepository } from './repositories.fixture';
import { TestRoles } from './roles.fixture';
import { BiometricRegistrationOptions } from '../../controllers';
import { BiometricRegistrationResponse } from '../../controllers/auth/biometric/biometric-registration-response.model';
import { VerifiedBiometricRegistration } from '../../controllers/auth/biometric/verified-biometric-registration.model';
import { BcryptUtilities } from '../../encapsulation/bcrypt.utilities';
import { Base64UrlString } from '../../encapsulation/webauthn.utilities';
import { BaseUser, BiometricCredentials, Credentials } from '../../models';
import { DefaultEntityOmitKeys } from '../../types';

/**
 * Sleeps for the given amount of milliseconds.
 * You need to await this to work.
 * @param ms - The amount of milliseconds everything should sleep.
 * @returns When the time has passed.
 */
export async function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Deletes everything in the test database.
 */
export async function clearDatabase(): Promise<void> {
    await testUserRepository.deleteAll();
    await testCredentialsRepository.deleteAll();
    await testBiometricCredentialsRepository.deleteAll();
    await testPasswordResetTokenRepository.deleteAll();
    await testRefreshTokenRepository.deleteAll();
}

/**
 * Creates an example user with the email 'user@example.com', the password 'stringstring' and the Roles [TestRoles.USER].
 * @returns The created user.
 */
export async function createExampleUser(): Promise<Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials'>> {
    const transaction: juggler.Transaction = await testDb.beginTransaction(IsolationLevel.READ_COMMITTED);
    try {
        const baseUser: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials' | 'biometricCredentials' | 'id'> = {
            email: 'user@example.com',
            roles: [TestRoles.USER]
        };
        const finishedBaseUser: BaseUser<TestRoles> = await testUserRepository.create(baseUser, { transaction: transaction });
        const credentials: Omit<Credentials, DefaultEntityOmitKeys | 'id' | 'baseUserId'> = {
            password: await BcryptUtilities.hash('stringstring')
        };
        await testUserRepository.credentials(finishedBaseUser.id).create(credentials, { transaction: transaction });
        await transaction.commit();
        return {
            id: finishedBaseUser.id,
            email: finishedBaseUser.email,
            roles: finishedBaseUser.roles,
            biometricCredentials: []
        };
    }
    catch (error) {
        await transaction.rollback();
        throw error;
    }
}

/**
 * Registers a biometric credential for the provided user.
 * @param user - The user to generate the credential for.
 */
export async function registerBiometricCredential(user: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials'>): Promise<void> {
    const options: BiometricRegistrationOptions = await testBiometricCredentialsService.generateRegistrationOptions(
        user.email,
        user.biometricCredentials ?? []
    );
    expect(options.user.name).to.equal(user.email);
    expect(options.attestation).to.equal('none');
    expect(options.authenticatorSelection?.userVerification).to.equal('preferred');
    expect(options.challenge).to.be.not.undefined();
    expect(options.rp.name).to.equal('localhost');
    expect(options.rp.id).to.equal('localhost');

    const PENDING: string = 'PENDING';
    const credentials: Omit<BiometricCredentials, DefaultEntityOmitKeys | 'id' | 'baseUserId'> = {
        challenge: options.challenge,
        credentialId: PENDING as Base64UrlString,
        publicKey: PENDING as Base64UrlString,
        counter: 0
    };
    const pendingCredential: BiometricCredentials = await testUserRepository.biometricCredentials(user.id).create(credentials);

    const baseUser: BaseUser<TestRoles> = await testUserRepository.findById(user.id, { include: [{ relation: 'biometricCredentials' }] });
    const existingBiometricCredential: BiometricCredentials | undefined = baseUser.biometricCredentials?.find(bc => {
        return bc.challenge === pendingCredential.challenge
            && bc.credentialId === PENDING
            && bc.counter === 0
            && bc.publicKey === PENDING;
    });

    expect(existingBiometricCredential).to.not.be.undefined();

    const mockRegistrationResponse: BiometricRegistrationResponse = {
        id: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' as Base64UrlString,
        rawId: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' as Base64UrlString,
        response: {
            clientDataJSON: btoa(JSON.stringify({
                type: 'webauthn.create',
                challenge: options.challenge,
                origin: 'https://localhost',
                crossOrigin: false
            })) as Base64UrlString,
            // eslint-disable-next-line stylistic/max-len
            attestationObject: 'o2NmbXRkbW9ja2dhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww==' as Base64UrlString
        },
        // authenticatorAttachment: 'cross-platform',
        clientExtensionResults: {},
        type: 'public-key'
    };

    try {
        const res: VerifiedBiometricRegistration = await testBiometricCredentialsService.verifyRegistrationResponse(
            mockRegistrationResponse,
            existingBiometricCredential?.challenge
        );

        expect(res.verified).to.be.true();

        if (res.verified && existingBiometricCredential) {
            await testBiometricCredentialsRepository.updateById(existingBiometricCredential.id, {
                credentialId: res.registrationInfo?.credentialID,
                publicKey: res.registrationInfo?.credentialPublicKey,
                counter: res.registrationInfo?.counter
            });
        }
    }
    catch (error) {
        // eslint-disable-next-line typescript/no-unsafe-member-access
        expect(error.message).to.equal('User verification required, but user could not be verified');
    }
}