/* eslint-disable jsdoc/require-jsdoc */
import { BaseBiometricCredentialsService } from '../../services';

export class BiometricCredentialsService extends BaseBiometricCredentialsService {
    protected override readonly RP_NAME: string = 'localhost';
    protected override readonly RP_DOMAIN: string = 'localhost';
}

export const testBiometricCredentialsService: BiometricCredentialsService = new BiometricCredentialsService();