import { middleware } from '../middleware/index';
import express from 'express';
import { controllers } from '../controllers';
const router = express.Router();

router.patch('/verification', middleware.authorization.isLoggedIn, controllers.accountSecurityController.verifyAccount)
router.patch('/login-pin', middleware.authorization.isLoggedIn, controllers.accountSecurityController.loginPin);
router.patch('/reset-pin', middleware.authorization.isLoggedIn, controllers.accountSecurityController.resetPin);

export const accountSecurityRouter = router


