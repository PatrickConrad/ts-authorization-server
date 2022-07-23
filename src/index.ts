import dotenv from "dotenv";
dotenv.config({path: __dirname+'/config/config.env'});
import { connectToDatabase, disconnectFromDatabase } from './config/database';
import { logger } from './config/logger';
import express, {Request, Response, NextFunction} from 'express';
import {corsSetup} from './config/cors';
import {router} from './router';

export const gracefulShutdown = (signal: string)=>{
    process.on(signal, async ()=>{
        server.close();
        await disconnectFromDatabase();
        process.exit(0);
    })
}

const app = express();

// if(process.env.NODE_ENV === 'development') app.use(morgan('dev'))

if(process.env.NODE_ENV === 'development') app.enable('trust proxy');

app.use((req: Request, res: Response, next: NextFunction) =>{
    corsSetup(req, res, next);
});

app.use((req: Request, res: Response, next: NextFunction)=>{
    console.log("IP",  req.ip, req.socket.remoteAddress)
    next()
})

app.use(express.json());

app.use(express.urlencoded({extended: true}));

app.get('/', (req: Request, res: Response, next: NextFunction)=>{
    res.send("Welcome to my api")
})
app.use('/api/v1', router);


const port = process.env.PORT || 8090
const server = app.listen(port, async () => {
    await connectToDatabase();
    logger.info(`Ready on port ${port}`);
})
.on("error", (e)=> logger.error(e,"Error starting server."));



 const signals = ["SIGTERM", "SIGINT"];

 for(let i = 0; i < signals.length; i++){
     gracefulShutdown(signals[i]);
 }