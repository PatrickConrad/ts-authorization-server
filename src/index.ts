import { helpers } from './helpers';
import dotenv from "dotenv";
dotenv.config({path: __dirname+'/config/config.env'});
import { connectToDatabase, disconnectFromDatabase } from './config/database';
import { logger } from './config/logger';
import express, {Request, Response, NextFunction} from 'express';
import {corsSetup} from './config/cors';
import {router} from './router';
import {utils} from './utils'
import path from 'path';

const app = express();
app.set('trust proxy', '127.0.0.1');

// if(process.env.NODE_ENV === 'development') app.use(morgan('dev'))

if(process.env.NODE_ENV === 'development') app.enable('trust proxy');

app.use((req: Request, res: Response, next: NextFunction) =>{
    corsSetup(req, res, next);
});

app.use(express.json());

app.use(express.urlencoded({extended: true}));

app.use((req: Request, res: Response, next: NextFunction)=>{
    console.log("IP",  req.ip, req.socket.remoteAddress)
    next()
})

app.get('/', async (req: Request, res: Response, next: NextFunction)=>{
    console.log("test")
    utils.keys.createKeys(process.env.ORGANIZATION_AUTH_TOKEN_PASSPHRASE as string, 'OrganizationAuth', path.join(__dirname, '../serverKeys'), 'save');

})

app.get('/ping', async (req: Request, res: Response, next: NextFunction)=>{
    res.status(200).json({success: true, message: "pong"});
})

app.use('/api/v1', router);

const port = process.env.PORT || 8090
const server = app.listen(port, async () => {
    await connectToDatabase();
    logger.info(`Ready on port ${port}`);
})
.on("error", (e)=> logger.error(e,"Error starting server."));

 process.on('SIGTERM'||"SIGINT", async ()=>{
    console.log("Server is shutting down")
    server.close();
    console.log("Database is closing")
    await disconnectFromDatabase();
    process.exit(0);
})