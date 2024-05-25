/* eslint-disable jsdoc/require-jsdoc */
import { testBiometricCredentialsService } from './biometric-credentials-service.fixture';
import { testDb } from './db.fixture';
import { testMailService } from './mail-service.fixture';
import { testBiometricCredentialsRepository, testPasswordResetTokenRepository, testRefreshTokenRepository, testUserRepository } from './repositories.fixture';
import { TestRoles } from './roles.fixture';
import { AccessTokenService, BaseUserService, RefreshTokenService } from '../../services';

export const testUserService: BaseUserService<TestRoles> = new BaseUserService<TestRoles>(
    testUserRepository,
    testPasswordResetTokenRepository,
    300000,
    testDb,
    testMailService,
    testBiometricCredentialsService,
    testBiometricCredentialsRepository
);
export const testAccessTokenService: AccessTokenService<TestRoles> = new AccessTokenService('accessSecret', 3600000);
export const testRefreshTokenService: RefreshTokenService<TestRoles> = new RefreshTokenService<TestRoles>(
    'refreshSecret',
    8640000000,
    'api',
    testUserRepository,
    testRefreshTokenRepository,
    testUserService,
    testAccessTokenService,
    3600000
);