import {Request, Response, NextFunction} from 'express';

export const corsSetup = (req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, Cookie");
    res.header("Access-Control-Allow-Credentials", 'true');
    res.header("Access-Control-Allow-Methods", "GET, PATCH, DELETE, POST");
    console.log(res.getHeaders())
    next();
}
