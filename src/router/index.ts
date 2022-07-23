

const router = require('express').Router();

router.use('/auth', authRouter);
router.use('/secondary-auth', secondaryAuthRouter)
router.use('/carrier', carrierRouter);
router.use('/admin', adminRouter);

export default {
    router
}

