import { model, Model, property } from '@loopback/repository';

/**
 * The Credentials used in the login.
 */
@model()
export class LoginCredentials extends Model {
    /**
     * The email of the user.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            format: 'email'
        }
    })
    email: string;
    /**
     * The password of the user.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            minLength: 12
        }
    })
    password: string;
}