import { organizationControllers } from './organizationControllers';
import { authController } from "./authControllers";
import { accountSecurityController } from "./accountSecurityController";
import { carriersController } from "./carrierController";
import { userController } from "./userController";
import { consentControllers } from './consentController';

export const controllers = {
    authController,
    accountSecurityController,
    carriersController,
    userController,
    organizationControllers,
    consentControllers
}