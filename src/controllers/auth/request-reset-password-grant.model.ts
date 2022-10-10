import { Model, model, property } from '@loopback/repository';

/**
 * The type of the request used for requesting the reset of a password.
 */
@model()
export class RequestResetPasswordGrant extends Model {
    /**
     * The email of the user for which the password reset should be requested.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            format: 'email'
        }
    })
    email: string;
}