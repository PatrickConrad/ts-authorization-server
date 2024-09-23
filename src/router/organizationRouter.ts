import { controllers } from './../controllers';
import express from 'express';
import { middleware } from '../middleware';
const router = express.Router();

router.get('/consent-screen', controllers.organizationControllers.preAuthConsentCheck);

export const organizationRouter = router


