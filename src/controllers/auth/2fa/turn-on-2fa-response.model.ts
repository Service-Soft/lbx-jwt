import { model, property } from '@loopback/repository';

/**
 * The response for turning on 2fa. Contains the qr code url.
 */
@model()
export class TurnOn2FAResponse {
    /**
     * The qr-code url that was generated.
     */
    @property({
        type: 'string',
        required: true
    })
    url: string;
}