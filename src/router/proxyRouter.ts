import { helpers } from '../helpers';
import { controllers } from './../controllers';
import express from 'express';

const router = express.Router();

router.post('/organization-authorization', helpers.useProxy)
export const proxyRouter = router;


