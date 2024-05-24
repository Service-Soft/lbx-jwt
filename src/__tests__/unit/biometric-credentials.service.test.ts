import { expect } from '@loopback/testlab';

import { BaseUser, BiometricCredentials } from '../../models';
import { DefaultEntityOmitKeys } from '../../types';
import { clearDatabase, createExampleUser, registerBiometricCredential } from '../fixtures/helpers';
import { testUserRepository } from '../fixtures/repositories.fixture';
import { TestRoles } from '../fixtures/roles.fixture';

let exampleUser: Omit<BaseUser<TestRoles>, DefaultEntityOmitKeys | 'credentials'>;

describe('BiometricCredentialsService', () => {
    before(async () => {
        await clearDatabase();
        exampleUser = await createExampleUser();
        await registerBiometricCredential(exampleUser);
    });

    it('should have a biometric credential registered correctly', async () => {
        const credentials: BiometricCredentials[] = await testUserRepository.biometricCredentials(exampleUser.id).find();
        expect(credentials.length).to.equal(1);
    });
});