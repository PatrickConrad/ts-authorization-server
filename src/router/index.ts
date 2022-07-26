import express from 'express';
import {authRouter} from './authRouter';
import {adminRouter} from './adminRouter';
import {secondaryAuthRouter} from './secondaryAuthRouter';
import {carrierRouter} from './carrierRouter'
const mainRouter = express.Router();

mainRouter.use('/auth', authRouter);
mainRouter.use('/secondary-auth', secondaryAuthRouter)
mainRouter.use('/carrier', carrierRouter);
mainRouter.use('/admin', adminRouter);

export const router = mainRouter


