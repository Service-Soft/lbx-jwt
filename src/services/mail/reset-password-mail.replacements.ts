/**
 * Defines replacements for the reset password mail template.
 */
export interface ResetPasswordMailReplacements {
    /**
     * The link to which the user gets send when he clicks "reset password".
     */
    link: string,
    /**
     * The first line of the email, most likely contains a greeting to the recipient.
     */
    firstLine: string,
    /**
     * The paragraphs to display before the reset password button.
     */
    paragraphsBeforeButton: string[],
    /**
     * The paragraphs to display after the reset password button.
     */
    paragraphsAfterButton: string[],
    /**
     * The label for the reset password button.
     */
    resetPasswordButtonLabel: string
}