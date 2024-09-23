import express from 'express';
import { controllers } from '../controllers';
import { middleware } from '../middleware';
const router = express.Router();

router.post('/register', middleware.authorization.isLoggedIn, controllers.authController.register);
router.post('/login', middleware.authorization.isLoggedIn, controllers.authController.login);
router.delete('/logout', middleware.authorization.hasAccess, controllers.authController.logout);
router.patch('/update-access', middleware.authorization.hasRefresh, controllers.authController.updateAccess);
router.patch('/update-refresh', middleware.authorization.hasRefresh, controllers.authController.updateRefresh);
router.patch('/forgot-password', middleware.authorization.isLoggedIn, controllers.authController.forgotPassword);
router.patch('/reset-password/:token', controllers.authController.resetPassword);
router.get('/google-auth', middleware.authorization.isLoggedIn, controllers.authController.googleAuth)
router.get('/sign-in-with-google', middleware.authorization.isLoggedIn, controllers.authController.goToGoogle)
router.post('/organization-authorization', controllers.authController.organizationAuthorization)

export const authRouter = router