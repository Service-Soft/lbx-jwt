import { readFileSync, writeFileSync } from 'fs';
import { HandlebarsUtilities } from '../../encapsulation/handlebars.utilities';
import { BaseUserWithRelations } from '../../models';
import { PasswordResetTokenWithRelations } from '../../models/password-reset-token.model';
import { Transporter } from 'nodemailer';
import { Email } from './email.model';
import { BaseDefaultDynamicReplacements, BaseDefaultStaticReplacements } from './base-default.replacements';
import { ResetPasswordMailReplacements } from './reset-password-mail.replacements';
import path from 'path';

export const LBX_JWT_MAIL_TEMPLATE_DIRECTORY: string = path.join(__dirname, '../mail/templates');

/**
 * A service that handles sending emails to users.
 */
export abstract class BaseMailService<
    RoleType extends string,
    DefaultStaticReplacementsType extends BaseDefaultStaticReplacements = BaseDefaultStaticReplacements
> {

    /**
     * The name of the mail address that sends any automated emails.
     */
    protected abstract readonly WEBSERVER_MAIL: string;

    /**
     * The base link before '.../token' for resetting the users password.
     */
    protected abstract readonly BASE_RESET_PASSWORD_LINK: string;

    /**
     * The path to the base email template.
     */
    protected readonly BASE_MAIL_TEMPLATE_PATH: string = `${LBX_JWT_MAIL_TEMPLATE_DIRECTORY}/base-mail.hbs`;

    /**
     * The email transporter that sends all the emails.
     */
    protected abstract readonly webserverMailTransporter: Transporter;

    /**
     * Whether or not this service is currently in production mode.
     * This is needed to determine if the email should be sent, or if the email content should be saved locally for testing purposes.
     */
    protected abstract readonly PRODUCTION: boolean;

    /**
     * The path where emails should be saved to when this service is not in production mode.
     */
    protected abstract readonly SAVED_EMAILS_PATH: string;

    /**
     * The url for the logo that is placed inside the header.
     */
    protected abstract readonly LOGO_HEADER_URL: string;

    /**
     * The width of the logo placed inside the header.
     */
    protected readonly LOGO_HEADER_WIDTH: number = 165;

    /**
     * The url for the logo that is placed inside the footer.
     */
    protected abstract readonly LOGO_FOOTER_URL: string;

    /**
     * The width of the logo placed inside the footer.
     */
    protected readonly LOGO_FOOTER_WIDTH: number = 500;

    /**
     * Lines of the address that is displayed inside the footer.
     */
    protected abstract readonly ADDRESS_LINES: string[];

    /**
     * A css color value for the address lines in the footer.
     */
    protected readonly ADDRESS_LINES_COLOR: string = '#999999';

    /**
     * A css color value for the background of emails.
     *
     * @default 'whitesmoke'
     */
    protected readonly BACKGROUND_COLOR: string = 'whitesmoke';

    /**
     * A css color value for the background of the content box of the email.
     *
     * @default 'white'
     */
    protected readonly CONTENT_BACKGROUND_COLOR: string = 'white';

    /**
     * A css color value for any text elements.
     *
     * @default '#363636'
     */
    protected readonly TEXT_COLOR: string = '#363636';

    /**
     * The default css font family value for text elements.
     *
     * @default 'Arial, sans-serif'
     */
    protected readonly DEFAULT_FONT_FAMILY: string = 'Arial, sans-serif';

    /**
     * A css color value for headline text elements.
     *
     * @default '#363636'
     */
    protected readonly HEADLINE_TEXT_COLOR: string = '#363636';

    /**
     * The css for button elements.
     */
    protected readonly BUTTON_CSS: string = `
        display: inline-block;
        font-weight: bold;
        padding: 15px;
        padding-left: 20px;
        padding-right: 20px;
        background-color: white;
        transition: background-color .3s;
        color: black;
        text-decoration: none;
        border-radius: 5px;
        box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.2), 0 4px 5px 0 rgba(0, 0, 0, 0.14), 0 1px 10px 0 rgba(0, 0, 0, 0.12);
    `;

    /**
     * The css for button elements that are hovered.
     */
    protected readonly BUTTON_HOVER_CSS: string = 'background-color: whitesmoke;';

    // eslint-disable-next-line jsdoc/require-returns
    /**
     * Defines static replacements that are useful for multiple email templates.
     *
     * By default this contains:
     * - addressLine1
     * - addressLine2
     * - logoHeaderUrl
     * - logoFooterUrl.
     *
     * Does not contain the html title, as this is unique per template and also not required.
     */
    protected get defaultStaticReplacements(): DefaultStaticReplacementsType {
        const res: BaseDefaultStaticReplacements = {
            addressLines: this.ADDRESS_LINES,
            addressLinesColor: this.ADDRESS_LINES_COLOR,
            logoHeaderUrl: this.LOGO_HEADER_URL,
            logoHeaderWidth: this.LOGO_HEADER_WIDTH,
            logoFooterUrl: this.LOGO_FOOTER_URL,
            logoFooterWidth: this.LOGO_FOOTER_WIDTH,
            backgroundColor: this.BACKGROUND_COLOR,
            contentBackgroundColor: this.CONTENT_BACKGROUND_COLOR,
            textColor: this.TEXT_COLOR,
            defaultFontFamily: this.DEFAULT_FONT_FAMILY,
            headlineTextColor: this.HEADLINE_TEXT_COLOR,
            buttonCss: this.BUTTON_CSS,
            buttonHoverCss: this.BUTTON_HOVER_CSS
        };
        return res as DefaultStaticReplacementsType;
    }

    constructor() {}

    /**
     * Sends an email for resetting the password of a specific user.
     * Contains a link that is active for a limited amount of time.
     *
     * @param user - The user that should receive the email.
     * @param resetToken - The reset token needed to generate the link.
     */
    async sendResetPasswordMail(user: BaseUserWithRelations<RoleType>, resetToken: PasswordResetTokenWithRelations): Promise<void> {
        const replacements: BaseDefaultStaticReplacements & BaseDefaultDynamicReplacements = {
            headline: 'Password Reset',
            title: 'Password Reset',
            content: this.getResetPasswordContent(resetToken, user),
            ...this.defaultStaticReplacements
        };

        const email: Email = {
            to: user.email,
            from: this.WEBSERVER_MAIL,
            subject: 'Password Reset',
            html: this.getTemplate(this.BASE_MAIL_TEMPLATE_PATH)(replacements)
        };
        await this.handleEmail(email);
    }

    /**
     * Gets the content for the reset password email.
     *
     * @param resetToken - The reset token needed for resetting the password.
     * @param user - The user that tries to reset his password.
     * @returns The finished html string that will be inserted inside the base template.
     */
    protected getResetPasswordContent(resetToken: PasswordResetTokenWithRelations, user: BaseUserWithRelations<RoleType>): string {
        const contentReplacements: ResetPasswordMailReplacements = {
            link: `${this.BASE_RESET_PASSWORD_LINK}/${resetToken.value}`,
            firstLine: this.getFirstLineForUser(user),
            paragraphsBeforeButton: [
                'someone requested to change the password for your account.',
                'Follow the link below to proceed:'
            ],
            resetPasswordButtonLabel: 'Reset Password',
            paragraphsAfterButton: [
                'This link is valid for the next 5 minutes.',
                'If you did not request to change your password, just ignore this email and your password will remain unchanged.'
            ]
        };
        return this.getTemplate(`${LBX_JWT_MAIL_TEMPLATE_DIRECTORY}/reset-password.hbs`)(contentReplacements);
    }

    /**
     * Defines what to do with the email.
     * In a production environment this sends the email to the recipients.
     * In a non production environment this saves the email data in a file for testing purposes.
     *
     * @param email - The email that should be handled.
     */
    protected async handleEmail(email: Email): Promise<void> {
        if (this.PRODUCTION) {
            await this.webserverMailTransporter.sendMail(email);
            return;
        }
        // for testing emails
        writeFileSync(`${this.SAVED_EMAILS_PATH}/${email.subject.replace(/ /g, '')}.test.html`, email.html);
    }

    /**
     * Gets the first line for the email based on the user the mail is sent to.
     * This can be used to address the user correctly.
     *
     * @param user - The user that should receive the email.
     * @returns The string that should be the first line inside the email.
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    protected getFirstLineForUser(user: BaseUserWithRelations<RoleType>): string {
        return 'Hi,';
    }


    /**
     * Gets the handlebars html template from the given path.
     *
     * @param path - The path of the template.
     * @returns The compiled handlebars template.
     */
    protected getTemplate(path: string): HandlebarsTemplateDelegate<unknown> {
        const sourceData: string = readFileSync(path, 'utf-8').toString();
        return HandlebarsUtilities.compile(sourceData);
    }
}