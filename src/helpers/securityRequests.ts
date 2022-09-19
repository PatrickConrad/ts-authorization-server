import { NextFunction, Request, Response } from "express";
import { utils } from "../utils";
import {TwoPointMidware} from '../interfaces/register'
import ErrorResponse from "../utils/errorResponse";


export const securityRequests = {
    sendSecurityPin: async (req: Request, res: Response, next: NextFunction)=>{
        const info: TwoPointMidware = req.body.midware.twoPoint;
        const {user, type} = info;
        const getPin = utils.keys.getPin();
        const pin = `${getPin}`;
        const hashedPin = await utils.keys.encryptPassword(pin);
        console.log("pin", pin)
        const tkn = await utils.jwts.signToken({id: user._id, hostname: req.hostname, type});
        if(!tkn.token) return next(new ErrorResponse("Error signing", 500));
        const {token} = tkn;
        console.log("EmailToken: ",tkn);
        if(type === 'login') {
            user.loginPin = hashedPin;
            user.loginToken = token; 
        }
        if(type === 'verify'){
            user.verifyPin = hashedPin;
            user.verificationToken = token;
        }
        if(type === 'forgot_password') {
            user.forgotPassToken = token;
            user.resetPin = hashedPin;
        }
        if(type === 'organization_verify'){
            user.verifyPin = hashedPin;
            user.verificationToken = token;
        }

        await user.save();
        res.cookie(
            type, 
            token,
            utils.cookies.setOptions(tkn.expires)
        )
        res.cookie(
            `${type}_initiated`,
            `true;${tkn.expires}`,
            utils.cookies.setOptions(tkn.expires, 'client')
        )
        
        if(user.twoPointPreference === 'email' || !user.phoneNumber || !user.phoneCarrierEmail){
            // const isSent = await sendMessage("email", user.email, type, pin);
            // if(!isSent) return next(new ErrorResponse("Pin not sent", 500));

            return res.status(201).json({
                success: true,
                twoPointAuth: true,
                type: 'email'
            })
        }
        const combinedEmail = user.phoneNumber + user.phoneCarrierEmail;
        // const isSent = await sendMessage("phone", combinedEmail, "verify", pin);
        // if(!isSent) return next(new ErrorResponse("Pin not sent", 500));
        return res.status(201).json({
            success: true,
            twoPointAuth: true,
            type: 'phone'
        })        
    }
}