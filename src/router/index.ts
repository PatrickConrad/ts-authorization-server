import express from 'express';
import {authRouter} from './authRouter';
import {adminRouter} from './adminRouter';
import {accountSecurityRouter} from './accountSecurity';
import {carrierRouter} from './carrierRouter'
import {organizationRouter} from './organizationRouter'
const mainRouter = express.Router();

mainRouter.use('/auth', authRouter);
mainRouter.use('/account-security', accountSecurityRouter)
mainRouter.use('/carrier', carrierRouter);
mainRouter.use('/admin', adminRouter);
mainRouter.use('/orgs', organizationRouter)


export const router = mainRouter


