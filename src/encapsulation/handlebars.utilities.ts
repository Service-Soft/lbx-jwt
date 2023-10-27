import { compile } from 'handlebars';

/**
 * Encapsulates functionality of the handlebars package.
 */
export abstract class HandlebarsUtilities {
    /**
     * Compiles the given data to a html template.
     * @param data - The data that should be compiled. This is usually the string result of reading an html file.
     * @returns The compiled templates.
     */
    static compile(data: unknown): HandlebarsTemplateDelegate<unknown> {
        return compile(data);
    }
}