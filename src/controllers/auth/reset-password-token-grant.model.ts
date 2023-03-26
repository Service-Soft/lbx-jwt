import { Model, model, property } from '@loopback/repository';

/**
 * The type of the request used for validating a reset password token.
 */
@model()
export class ResetPasswordTokenGrant extends Model {
    /**
     * The value of the reset password token.
     */
    @property({
        type: 'string',
        required: true
    })
    value: string;
}