import { model, property } from '@loopback/repository';

/**
 * The response that gets sent when a user tries to login that requires resetting his password.
 */
@model()
export class RequirePasswordChangeResponseModel {
    /**
     * Whether or not 2fa is required.
     */
    @property({
        type: 'boolean',
        required: true
    })
    requirePasswordChange: boolean;
}