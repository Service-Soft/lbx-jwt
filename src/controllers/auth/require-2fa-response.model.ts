import { model, property } from '@loopback/repository';

/**
 * The response that gets sent when a user tries to login that requires 2fa.
 */
@model()
export class Require2FAResponseModel {
    /**
     * Whether or not 2fa is required.
     */
    @property({
        type: 'boolean',
        required: true
    })
    require2fa: boolean;
}