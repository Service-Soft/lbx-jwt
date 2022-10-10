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
     * The subject of the email.
     */
    subject: string,
    /**
     * The html content of the email.
     */
    html: string
}