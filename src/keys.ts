/* eslint-disable stylistic/max-len */

import { BindingKey } from '@loopback/core';

import { AccessTokenService, BaseMailService, BaseUserService, BaseBiometricCredentialsService, RefreshTokenService, TwoFactorService } from './services';

const ONE_HUNDRED_DAYS_IN_MS: number = 8640000000;
const HOUR_IN_MS: number = 3600000;
const FIVE_MINUTES_IN_MS: number = 300000;

/**
 * Contains all values which have defaults.
 */
interface DefaultValues {
    /**
     * The amount of milliseconds after which the access token expires.
     * @default 3600000 // 1 hour
     */
    readonly ACCESS_TOKEN_EXPIRES_IN_MS: number,
    /**
     * The amount of milliseconds after which the refresh token expires.
     * @default 8640000000 // 100 days
     */
    readonly REFRESH_TOKEN_EXPIRES_IN_MS: number,
    /**
     * The refresh token issuer stored inside the refresh token.
     * @default 'api'
     */
    readonly REFRESH_TOKEN_ISSUER: string,
    /**
     * The amount of time that the password reset token is active.
     */
    readonly PASSWORD_RESET_TOKEN_EXPIRES_IN_MS: number
}

/**
 * Default Values for the component.
 */
export const LbxJwtDefaultValues: DefaultValues = {
    ACCESS_TOKEN_EXPIRES_IN_MS: HOUR_IN_MS,
    REFRESH_TOKEN_EXPIRES_IN_MS: ONE_HUNDRED_DAYS_IN_MS,
    REFRESH_TOKEN_ISSUER: 'api',
    PASSWORD_RESET_TOKEN_EXPIRES_IN_MS: FIVE_MINUTES_IN_MS
};

/**
 * Bindings to customize the LbxJwt component.
 */
// eslint-disable-next-line typescript/no-namespace
export namespace LbxJwtBindings {
    /**
     * The key for the secret used to generate access tokens.
     */
    export const ACCESS_TOKEN_SECRET: BindingKey<string> = BindingKey.create<string>('lbx.jwt.access.token.secret');
    /**
     * The key for the amount of milliseconds after which the access token expires.
     * @default 3600000 // 1 hour
     */
    export const ACCESS_TOKEN_EXPIRES_IN_MS: BindingKey<number> = BindingKey.create<number>('lbx.jwt.access.token.expires.in.ms');
    /**
     * The key for the service that handles generating and validating access tokens.
     */
    export const ACCESS_TOKEN_SERVICE: BindingKey<AccessTokenService<string>>
        = BindingKey.create<AccessTokenService<string>>('lbx.jwt.access.token.service');

    /**
     * The key for the service that handles verifying user credentials.
     */
    export const BASE_USER_SERVICE: BindingKey<BaseUserService<string>> = BindingKey.create<BaseUserService<string>>('lbx.jwt.user.service');
    /**
     * The key of the datasource.
     */
    export const DATASOURCE_KEY: string = 'datasources.db';
    /**
     * The key of the repository responsible for handling users.
     */
    export const BASE_USER_REPOSITORY: string = 'repositories.BaseUserRepository';
    /**
     * The key of the repository responsible for handling user credentials.
     */
    export const CREDENTIALS_REPOSITORY: string = 'repositories.CredentialsRepository';

    /**
     * The key for the secret used to generate refresh tokens.
     */
    export const REFRESH_TOKEN_SECRET: BindingKey<string> = BindingKey.create<string>('lbx.jwt.refresh.token.secret');
    /**
     * The key for the amount of milliseconds after which the refresh token expires.
     * @default 8640000000 // 100 days
     */
    export const REFRESH_TOKEN_EXPIRES_IN_MS: BindingKey<number> = BindingKey.create<number>('lbx.jwt.refresh.token.expires.in.ms');
    /**
     * The key for the service that handles refresh tokens.
     */
    export const REFRESH_TOKEN_SERVICE: BindingKey<RefreshTokenService<string>>
        = BindingKey.create<RefreshTokenService<string>>('lbx.jwt.refresh.token.service');
    /**
     * The key for the refresh token issuer stored inside the refresh token..
     * @default 'api'
     */
    export const REFRESH_TOKEN_ISSUER: BindingKey<string> = BindingKey.create<string>('lbx.jwt.refresh.token.issuer');
    /**
     * The key of the backend datasource for refresh token's persistency.
     */
    export const REFRESH_TOKEN_DATASOURCE_KEY: string = 'datasources.db';
    /**
     * Key for the repository that stores the refresh token and its bound user information.
     */
    export const REFRESH_TOKEN_REPOSITORY: string = 'repositories.RefreshTokenRepository';

    /**
     * The key for the amount of milliseconds after which the reset password token expires.
     * @default 300000 // 5 minutes
     */
    export const PASSWORD_RESET_TOKEN_EXPIRES_IN_MS: BindingKey<number> = BindingKey.create<number>('lbx.jwt.password.reset.token.expires.in.ms');
    /**
     * The key for the repository that stores the password reset token.
     */
    export const PASSWORD_RESET_TOKEN_REPOSITORY: string = 'repositories.PasswordResetTokenRepository';
    /**
     * The key for the service that handles sending emails.
     */
    export const MAIL_SERVICE: BindingKey<BaseMailService<string>> = BindingKey.create<BaseMailService<string>>('lbx.jwt.email.service');

    /**
     * Provider for all possible role values.
     */
    export const ROLES: BindingKey<string[]> = BindingKey.create<string[]>('lbx.jwt.roles');

    /**
     * The label to display inside the two factor app.
     */
    export const TWO_FACTOR_LABEL: BindingKey<string> = BindingKey.create('lbx.jwt.two.factor.label');
    /**
     * Whether or not two factor authentication should be forced. If set to true a user is only allowed to login,
     * any other request leads to an error if two factor authentication is disabled.
     */
    export const FORCE_TWO_FACTOR: BindingKey<boolean> = BindingKey.create('lbx.jwt.two.factor.force');
    /**
     * Routes that should be accessible even if two factor authentication is disabled for the user.
     * By default this is the login route.
     */
    export const FORCE_TWO_FACTOR_ALLOWED_ROUTES: BindingKey<string[]> = BindingKey.create('lbx.jwt.two.factor.force.allowed.routes');
    /**
     * The custom header for request where the two factor code is provided.
     * Defaults to 'X-Authorization-2FA'.
     */
    export const TWO_FACTOR_HEADER: BindingKey<string> = BindingKey.create('lbx.jwt.two.factor.header');
    /**
     * Provider for the two factor service.
     */
    export const TWO_FACTOR_SERVICE: BindingKey<TwoFactorService<string>> = BindingKey.create<TwoFactorService<string>>('lbx.jwt.two.factor.service');

    /**
     * Provider for the biometric credentials service.
     */
    export const BIOMETRIC_CREDENTIALS_SERVICE: BindingKey<BaseBiometricCredentialsService> = BindingKey.create<BaseBiometricCredentialsService>('lbx.jwt.biometrics.credentials.service');
    /**
     * The key for the repository that stores the password reset token.
     */
    export const BIOMETRIC_CREDENTIALS_REPOSITORY: string = 'repositories.BiometricCredentialsRepository';
}