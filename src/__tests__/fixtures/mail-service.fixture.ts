/* eslint-disable jsdoc/require-jsdoc */
import { Transporter } from 'nodemailer';

import { TestRoles } from './roles.fixture';
import { BaseMailService } from '../../services';

export class MailService extends BaseMailService<TestRoles> {

    protected readonly WEBSERVER_MAIL: string = 'webserver@test.com';

    protected readonly BASE_RESET_PASSWORD_LINK: string = 'http://localhost:4200/reset-password';

    protected readonly webserverMailTransporter: Transporter;

    protected readonly PRODUCTION: boolean = false;

    protected readonly SAVED_EMAILS_PATH: string = './test-emails';

    protected override readonly LOGO_HEADER_URL: string = 'https://via.placeholder.com/165x165';

    protected override readonly LOGO_FOOTER_URL: string = 'https://via.placeholder.com/500x60';

    protected readonly ADDRESS_LINES: string[] = ['my address', 'my name'];
}

export const testMailService: MailService = new MailService();