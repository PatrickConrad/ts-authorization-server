import { models } from '../models/index';
import { utils } from '../utils';
import { NextFunction, Request, Response } from "express";
import { VerifiedToken, Payload } from '../types/imports';
import { ObjectId } from 'mongoose';


export const organizationControllers = {
    preAuthConsentCheck: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const type = req.query.type as string;
            const redirect = req.query.redirect as string;
            const orgId = req.query.orgId as string;
            if(!type || !orgId || !redirect){
                return res.status(404).json({
                    success: false,
                    message: `Please supply all needed query parameters. Missing: ${!type?" -type- ":''}${!redirect?' -redirect- ':''}${!orgId?' -orgId- ':''}`
                })
            }
            const hasAccess = utils.cookies.getCookie(req, 'access') as string;
            if(!hasAccess){
                return console.log("No access")
            }
            const verified = utils.jwts.verifyToken(hasAccess, 'access') as VerifiedToken;
            const pl = verified.payload as Payload;
            if(!verified.isVerified || verified.expired || !pl.id){
                return console.log("No access")
            }
            const user = await models.User.findById(pl.id);
            if(!user){
                return console.log("No user found")
            }
            const orgConsentAccessToken = utils.jwts.signToken({id: pl.id as ObjectId, username: user.username, hostname: req.hostname, type: 'org_consent'})
            if(!orgConsentAccessToken || !orgConsentAccessToken.token){
                return console.log("Not able to verify")
            }
            res.cookie(
                "access",
                orgConsentAccessToken.token,
                utils.cookies.setOptions(orgConsentAccessToken.expires)
            )
            return res.redirect(`http://localhost:8091/api/v1/consent/consent-screen?type=${type}&orgId=${orgId}&redirect=${redirect}`)

        }
        catch(err){
            next(err)
        }
    }
}