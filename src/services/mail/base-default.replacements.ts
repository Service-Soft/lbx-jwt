/**
 * Any dynamic replacements that are used through multiple emails but have a unique value for each.
 */
export interface BaseDefaultDynamicReplacements {
    /**
     * The html title of the email.
     * Is displayed as preview in the email client.
     */
    title: string,
    /**
     * The headline of the email.
     */
    headline: string,
    /**
     * The content that should be placed inside the base email template.
     */
    content: string
}

/**
 * The base type for static replacements used in email templates.
 */
export interface BaseDefaultStaticReplacements {
    /**
     * A css color value for the background of the email.
     */
    backgroundColor: string,
    /**
     * A css color value for the background of the content box of the email.
     */
    contentBackgroundColor: string,
    /**
     * A css color value for the text of the email.
     */
    textColor: string,
    /**
     * The default font family to use.
     * Is needed to override settings of some email clients.
     */
    defaultFontFamily: string,
    /**
     * The lines of the address.
     * Gets displayed at the bottom of the email.
     */
    addressLines: string[],
    /**
     * The url of the logo to display at the top of the email.
     */
    logoHeaderUrl: string,
    /**
     * The width of the logo inside the header of the email.
     */
    logoHeaderWidth: number,
    /**
     * The url of the logo to display at the bottom of the email.
     */
    logoFooterUrl: string,
    /**
     * The width of the logo inside the footer.
     */
    logoFooterWidth: number,
    /**
     * A css color value for the headline of the email.
     */
    headlineTextColor: string,
    /**
     * The css for the button.
     */
    buttonCss: string,
    /**
     * The css for buttons when hovered.
     */
    buttonHoverCss: string,
    /**
     * A css color value for the address lines in the footer.
     */
    addressLinesColor: string
}