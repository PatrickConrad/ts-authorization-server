import { organizationControllers } from './organizationControllers';
import { authController } from "./authControllers";
import { accountSecurityController } from "./accountSecurityController";
import { carriersController } from "./carrierController";
import { userController } from "./userController";

export const controllers = {
    authController,
    accountSecurityController,
    carriersController,
    userController,
    organizationControllers
}