import { injectable, /* inject, */ BindingScope } from '@loopback/core';
import { BaseMailService } from 'lbx-jwt';
import { Transporter } from 'nodemailer';
import path from 'path';
import { Roles } from '../models/roles.enum';

/**
 * The service responsible for sending emails.
 */
@injectable({ scope: BindingScope.TRANSIENT })
export class MailService extends BaseMailService<Roles> {
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly WEBSERVER_MAIL: string = 'webserver@test.com';
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly BASE_RESET_PASSWORD_LINK: string = 'http://localhost:4200/reset-password';
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly webserverMailTransporter: Transporter;
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly PRODUCTION: boolean = false;
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly SAVED_EMAILS_PATH: string = path.join(__dirname, '../../../test-emails');
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly LOGO_HEADER_URL: string = 'https://via.placeholder.com/165x165';
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly LOGO_FOOTER_URL: string = 'https://via.placeholder.com/500x60';
    // eslint-disable-next-line jsdoc/require-jsdoc
    protected readonly ADDRESS_LINES: string[] = ['my address', 'my name'];
}