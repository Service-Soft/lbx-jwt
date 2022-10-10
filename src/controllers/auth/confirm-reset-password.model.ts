import { Model, model, property } from '@loopback/repository';

/**
 * The type of the request used for resetting a password.
 */
@model()
export class ConfirmResetPassword extends Model {
    /**
     * The reset password token.
     */
    @property({
        type: 'string',
        required: true
    })
    resetToken: string;

    /**
     * The new password of the user.
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