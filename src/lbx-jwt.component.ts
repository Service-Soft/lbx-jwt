import { registerAuthenticationStrategy } from '@loopback/authentication';
import { Application, Binding, Component, CoreBindings, createBindingFromClass, inject } from '@loopback/core';
import { LbxJwtBindings, LbxJwtDefaultValues } from './keys';
import { RefreshTokenRepository, CredentialsRepository, BaseUserRepository } from './repositories';
import { BaseUserService, RefreshTokenService } from './services';
import { JwtAuthenticationStrategy } from './services/jwt.auth.strategy';
import { AccessTokenService } from './services/access-token.service';
import { SecuritySpecEnhancer } from './services/security.spec.enhancer';
import { PasswordResetTokenRepository } from './repositories/password-reset-token.repository';

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