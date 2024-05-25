/* eslint-disable stylistic/max-len */
/* eslint-disable jsdoc/require-jsdoc */
import { Getter } from '@loopback/core';

import { testDb } from './db.fixture';
import { TestRoles } from './roles.fixture';
import { BaseUserRepository, BiometricCredentialsRepository, CredentialsRepository, PasswordResetTokenRepository, RefreshTokenRepository } from '../../repositories';

export const testCredentialsRepository: CredentialsRepository = new CredentialsRepository(testDb);
const credentialsRepositoryGetter: Getter<CredentialsRepository> = async () => testCredentialsRepository;
export const testBiometricCredentialsRepository: BiometricCredentialsRepository = new BiometricCredentialsRepository(testDb);
const biometricCredentialsRepositoryGetter: Getter<BiometricCredentialsRepository> = async () => testBiometricCredentialsRepository;
export const testUserRepository: BaseUserRepository<TestRoles> = new BaseUserRepository(testDb, credentialsRepositoryGetter, biometricCredentialsRepositoryGetter);
const baseUserRepositoryGetter: Getter<BaseUserRepository<TestRoles>> = async () => testUserRepository;
export const testPasswordResetTokenRepository: PasswordResetTokenRepository<TestRoles> = new PasswordResetTokenRepository(testDb, baseUserRepositoryGetter);
export const testRefreshTokenRepository: RefreshTokenRepository = new RefreshTokenRepository(testDb);