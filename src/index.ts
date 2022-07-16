import { cookieExtractor, getCookie } from './utils/cookies';
import { token } from './utils/jwts';
import { connectToDatabase, disconnectFromDatabase } from './config/database';
import { logger } from './config/logger';
import express, {Request, Response, NextFunction} from 'express';
import dotenv from 'dotenv';

dotenv.config({path: __dirname+'/config/config.env'});

const gracefulShutdown = (signal: string)=>{
    process.on("SIGTERM"||"SIGINT", async ()=>{
        server.close();
        await disconnectFromDatabase();
        process.exit(0);
    })
}

const app = express();
app.get('/', (req: Request, res: Response)=>{
    const tkn = token();
    res.cookie('refresh', tkn, {
        httpOnly: true,
        maxAge: 5000000     
    })
    res.cookie('access', tkn, {
        httpOnly: true,
        maxAge: 5000000     
    })
    res.status(200).send({test: 'hi'})
})
app.get('/test', (req: Request, res: Response)=>{
    console.log({cooks: req.headers.cookie});
    console.log(getCookie(req, 'access'));
    console.log(getCookie(req, 'refresh'));

})

const port = process.env.PORT || 8999
 const server = app.listen(port, async () => {
    await connectToDatabase();
    logger.info(`Ready on port ${port}`);
 })
 .on("error", (e)=> logger.error(e,"Error starting server."));



 const signals = ["SIGTERM", "SIGINT"];

 for(let i = 0; i < signals.length; i++){
     gracefulShutdown(signals[i]);
 }