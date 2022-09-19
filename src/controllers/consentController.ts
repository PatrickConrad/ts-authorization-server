import { NextFunction, Request, Response } from "express";
import { utils } from "../utils";
import ErrorResponse from "../utils/errorResponse";
import { memoryCache } from "../config/cache";
import { consentResponse } from "../utils/iframeMessaging";
import { AuthIframe } from "../utils/iframeClass";
import url from 'url';

export const consentControllers = {
    getConsentPage: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const id = req.query.id as string;
            const orgName = req.query.orgName as string;
            const scopes = req.query.orgName as string;
            const redirect = req.query.orgName as string;
            const type = req.query.orgName as string;
            if(!id || !orgName || !scopes || !redirect) return new ErrorResponse('must include all required information', 401);
            const query = new URLSearchParams({id, orgName, scopes, redirect, type});
            const src = `http://localhost:3001/auth/consent?${query}`
            const windowToken = utils.jwts.signToken({
                type:  'consent',
                id: req.ip, 
                hostname: req.hostname 
            })

            const authClass = new AuthIframe(req.protocol+'://'+req.get('host'), JSON.stringify(windowToken))
            const resConsent = consentResponse(src, authClass)            
            return res.status(200).json({
                success: true,
                resConsent
            })

        }
        catch(err){
            next(err)
        }
    }
}