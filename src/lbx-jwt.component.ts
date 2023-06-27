import { registerAuthenticationStrategy } from '@loopback/authentication';
import { Application, Binding, Component, CoreBindings, createBindingFromClass, inject } from '@loopback/core';
import { LbxJwtBindings, LbxJwtDefaultValues } from './keys';
import { BaseUserRepository, CredentialsRepository, RefreshTokenRepository } from './repositories';
import { PasswordResetTokenRepository } from './repositories/password-reset-token.repository';
import { BaseUserService, RefreshTokenService, TwoFactorService } from './services';
import { AccessTokenService } from './services/access-token.service';
import { JwtAuthenticationStrategy } from './services/jwt.auth.strategy';
import { SecuritySpecEnhancer } from './services/security.spec.enhancer';

/**
 * Provides out of the box jwt functionality.
 * Includes roles inside the token and provides refresh and reuse detection.
 */
export class LbxJwtComponent implements Component {
    // eslint-disable-next-line jsdoc/require-jsdoc
    bindings: Binding[] = [
        // access token bindings
        Binding.bind(LbxJwtBindings.ACCESS_TOKEN_EXPIRES_IN_MS).to(LbxJwtDefaultValues.ACCESS_TOKEN_EXPIRES_IN_MS),
        Binding.bind(LbxJwtBindings.ACCESS_TOKEN_SERVICE).toClass(AccessTokenService),

        // user bindings
        Binding.bind(LbxJwtBindings.BASE_USER_SERVICE).toClass(BaseUserService),
        Binding.bind(LbxJwtBindings.BASE_USER_REPOSITORY).toClass(BaseUserRepository),
        Binding.bind(LbxJwtBindings.CREDENTIALS_REPOSITORY).toClass(CredentialsRepository),

        // refresh token bindings
        Binding.bind(LbxJwtBindings.REFRESH_TOKEN_SERVICE).toClass(RefreshTokenService),
        Binding.bind(LbxJwtBindings.REFRESH_TOKEN_EXPIRES_IN_MS).to(LbxJwtDefaultValues.REFRESH_TOKEN_EXPIRES_IN_MS),
        Binding.bind(LbxJwtBindings.REFRESH_TOKEN_ISSUER).to(LbxJwtDefaultValues.REFRESH_TOKEN_ISSUER),
        Binding.bind(LbxJwtBindings.REFRESH_TOKEN_REPOSITORY).toClass(RefreshTokenRepository),

        // password reset token bindings
        Binding.bind(LbxJwtBindings.PASSWORD_RESET_TOKEN_EXPIRES_IN_MS).to(LbxJwtDefaultValues.PASSWORD_RESET_TOKEN_EXPIRES_IN_MS),
        Binding.bind(LbxJwtBindings.PASSWORD_RESET_TOKEN_REPOSITORY).toClass(PasswordResetTokenRepository),

        // two factor authentication
        Binding.bind(LbxJwtBindings.FORCE_TWO_FACTOR).to(false),
        Binding.bind(LbxJwtBindings.FORCE_TWO_FACTOR_ALLOWED_ROUTES).to(['login']),
        Binding.bind(LbxJwtBindings.TWO_FACTOR_HEADER).to('X-Authorization-2FA'),
        Binding.bind(LbxJwtBindings.TWO_FACTOR_SERVICE).toClass(TwoFactorService),

        // OpenApi
        createBindingFromClass(SecuritySpecEnhancer)
    ];

    constructor(
        @inject(CoreBindings.APPLICATION_INSTANCE)
        private readonly app: Application
    ) {
        registerAuthenticationStrategy(app, JwtAuthenticationStrategy);
    }
}