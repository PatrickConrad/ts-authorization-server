import { utils } from '../utils';
import { NextFunction, Request, Response } from "express";
import {helpers} from '../helpers';
import { models } from '../models'
import ErrorResponse from '../utils/errorResponse';
import { ObjectId } from 'mongoose';

interface Payload {
    id: ObjectId
}



export const authorization = {
    isLoggedIn: async(req: Request, res: Response, next: NextFunction) => {
        try{
        const refreshToken = await utils.cookies.getCookie(req, "refresh");
            if(!refreshToken){
                return next()
            }
            console.log({refreshToken})

            return res.status(400).json({
                message: 'Already logged in',
                success: false
            });
        }
        catch(err){
            next(err)
        }
    },
    hasAccess: async(req: Request, res: Response, next: NextFunction) => {
        try{
            console.log("REQUEST: ", req.cookies)
            const accessToken = await utils.cookies.getCookie(req, "access");
            console.log("ACCESSTOKEN", accessToken)
            if(!accessToken){
                return res.status(401).json({
                    success: false,
                    message: "Access Denied"
                });
            }
            const accessData = await utils.jwts.verifyToken(accessToken as string, "access");
            const pl = accessData.payload as Payload
            if(accessData.expired || !accessData.isVerified){
                await res.clearCookie('access');
                return res.status(401).json({
                    success: false,
                    message: "Access Denied: expired"
                });
            }
        
            req.body.midware.user = pl.id;   
            next()
        }
        catch(err){
            next(err)
        }
    },
    hasRefresh: async(req: Request, res: Response, next: NextFunction) => {
        try{
            const refreshToken = await utils.cookies.getCookie(req, "refresh");
            if(!refreshToken) return next(new ErrorResponse("Access Denied", 401));
            const refreshData = await utils.jwts.verifyToken(refreshToken as string, "refresh");
            const pl = refreshData.payload as Payload
            if(refreshData.expired || !refreshData.isVerified){
                await res.clearCookie('refresh');
                await res.clearCookie('access');
                await helpers.cache.clearCache(refreshToken as string);       
                return res.status(401).json({
                    success: false,
                    message: "Access Denied: no long term authority"
                });
            }
            
            req.body.midware.user = pl.id;
            req.body.midware.token= refreshToken as string;
            req.body.midware.isLoggedIn = true
            next()
        }
        catch(err){
            next(err)
        }
    },
    isAdmin: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const id: ObjectId = req.body.midware.user;
            if(!id) {
                return res.status(401).json({
                    success: false,
                    message: "Accessing user not found"
                })
            }
            const user = await models.User.findById(id);
            if(!user) {
                return res.status(500).json({
                    success: false,
                    message: "Access Denied: no user"
                });
            }
            if(!user.isAdmin){
                return res.status(401).json({
                    success: false,
                    message: "You do not have permission to view this content: Access Denied"
                });
            }
            
            req.body.midware.admin = true;
            req.body.midware.currentUser = user;   
            next();
        }
        catch(err){
            next(err)
        }
    }
}
