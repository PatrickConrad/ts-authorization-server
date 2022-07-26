import {Request, Response, NextFunction} from 'express';

export const corsSetup = (req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "http://127.0.0.1:5500");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept,");
    res.header("Access-Control-Allow-Credentials", 'true');
    res.header("Access-Control-Allow-Methods", "GET, PUT, DELETE, POST");
    next();
}
