import cookies from './utils/cookies';
import jwts from './utils/jwts';
import keys from './utils/keys';
import { connectToDatabase, disconnectFromDatabase } from './config/database';
import { logger } from './config/logger';
import express, {Request, Response, NextFunction} from 'express';
import dotenv from "dotenv";

dotenv.config({path: __dirname+'/config/config.env'});

const {createDiffie, getPublicDiffie, getSharedSecret} = keys;
const gracefulShutdown = ()=>{
    logger.info("now shutting server down")    
    server.close();
    logger.info("now shutting down")
    process.exit(0);
}

const app = express();
app.get('/', (req: Request, res: Response)=>{
    //diffie test
    const bob = createDiffie('secp256k1');
    const alice = createDiffie('secp256k1');
    const bobShared = getSharedSecret(bob.diffie, alice.keys);
    const aliceShared =  getSharedSecret(alice.diffie, bob.keys);
    console.log({secrets: {bobShared, aliceShared}})
    console.log(bobShared === aliceShared);
})

//     const tkn = jwts.signToken();
//     res.cookie('refresh', tkn, {
//         httpOnly: true,
//         maxAge: 5000000     
//     })
//     res.cookie('access', tkn, {
//         httpOnly: true,
//         maxAge: 5000000     
//     })
//     res.status(200).send({test: 'hi'})
// })
// app.get('/test', (req: Request, res: Response)=>{
//     console.log({cooks: req.headers.cookie});
//     console.log(getCookie(req, 'access'));
//     console.log(getCookie(req, 'refresh'));

// })

const port = process.env.PORT || 8999
 const server = app.listen(port, async () => {
    // await connectToDatabase();
    logger.info(`Ready on port ${port}`);
 })
 .on("error", (e)=> logger.error(e,"Error starting server."));
