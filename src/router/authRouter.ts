import express from 'express';
import { controllers } from '../controllers';
const router = express.Router();

router.post('/register', controllers.authController.register)

export const authRouter = router



