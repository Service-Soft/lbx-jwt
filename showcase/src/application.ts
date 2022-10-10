import { BootMixin } from '@loopback/boot';
import { ApplicationConfig } from '@loopback/core';
import { RestExplorerBindings, RestExplorerComponent } from '@loopback/rest-explorer';
import { RepositoryMixin } from '@loopback/repository';
import { RestApplication } from '@loopback/rest';
import { ServiceMixin } from '@loopback/service-proxy';
import path from 'path';
import { MySequence } from './sequence';
import { BaseUserRepository, CredentialsRepository, LbxJwtBindings, LbxJwtComponent, RefreshTokenRepository, PasswordResetTokenRepository, LbxJwtAuthController } from 'lbx-jwt';
import { MailService } from './services';
import { AuthenticationComponent } from '@loopback/authentication';
import { AuthorizationBindings, AuthorizationComponent, AuthorizationDecision, AuthorizationOptions } from '@loopback/authorization';

export { ApplicationConfig };

/**
 * The application class.
 */
export class ShowcaseApplication extends BootMixin(ServiceMixin(RepositoryMixin(RestApplication))) {
    constructor(options: ApplicationConfig = {}) {
        super(options);

        // Set up the custom sequence
        this.sequence(MySequence);

        // Set up default home page
        this.static('/', path.join(__dirname, '../public'));

        // Customize @loopback/rest-explorer configuration here
        this.configure(RestExplorerBindings.COMPONENT).to({
            path: '/explorer'
        });
        this.component(RestExplorerComponent);

        this.component(AuthenticationComponent);
        this.component(LbxJwtComponent);
        this.bind(LbxJwtBindings.ACCESS_TOKEN_SECRET).to('JwtS3cr3t');
        this.bind(LbxJwtBindings.REFRESH_TOKEN_SECRET).to('JwtR3fr3shS3cr3t');
        this.bind(LbxJwtBindings.MAIL_SERVICE).toClass(MailService);
        this.repository(BaseUserRepository);
        this.repository(CredentialsRepository);
        this.repository(RefreshTokenRepository);
        this.repository(PasswordResetTokenRepository);
        this.controller(LbxJwtAuthController);

        const authOptions: AuthorizationOptions = {
            precedence: AuthorizationDecision.DENY,
            defaultDecision: AuthorizationDecision.DENY
        };
        this.configure(AuthorizationBindings.COMPONENT).to(authOptions);
        this.component(AuthorizationComponent);

        this.projectRoot = __dirname;
        // Customize @loopback/boot Booter Conventions here
        this.bootOptions = {
            controllers: {
                // Customize ControllerBooter Conventions here
                dirs: ['controllers'],
                extensions: ['.controller.js'],
                nested: true
            }
        };
    }
}