import { Attachment } from 'nodemailer/lib/mailer';

/**
 * The base information for an email that can be send with nodemailer.
 */
export interface Email {
    /**
     * The recipient/s that should receive the email.
     */
    to: string | string[],
    /**
     * The mail account that sends the email.
     */
    from: string,
    /**
     * The sender of the email. Can differ from the email that technically sends the email.
     */
    sender?: string,
    /**
     * The cc field of the email.
     */
    cc?: string,
    /**
     * The bcc field of the email.
     */
    bcc?: string,
    /**
     * Any attachments of the email.
     */
    attachments?: Attachment[],
    /**
     * The subject of the email.
     */
    subject: string,
    /**
     * The html content of the email.
     */
    html: string
}