import { controllers } from './../controllers';
import express from 'express';
import { middleware } from '../middleware';
const router = express.Router();

router.get('/carriers', controllers.carriersController.getAllCarriers);
router.get('/carrier/:id', middleware.authorization.hasAccess, controllers.carriersController.getCarrier);
router.post('/carrier', middleware.authorization.hasAccess, middleware.authorization.isAdmin, controllers.carriersController.addCarrier);
router.delete('/carrier/:id', middleware.authorization.hasAccess, middleware.authorization.isAdmin, controllers.carriersController.deleteCarrier);

export const carrierRouter = router


