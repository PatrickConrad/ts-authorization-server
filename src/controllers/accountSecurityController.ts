import { NextFunction, Request, Response } from "express"
import {RegisterUser} from '../interfaces/register'
import ErrorResponse from '../utils/errorResponse'
import {utils} from '../utils'
import {models} from '../models';
import { ObjectId } from "mongoose";
import {helpers} from '../helpers';

export interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: ObjectId | string,
    iss: string,
    tai: number | string
}

interface UserInfo {
    iss: string,
    azp: string,
    aud: string,
    sub: string,
    email: string,
    email_verified: string,
    at_hash: string,
    name: string,
    picture: string,
    given_name: string,
    family_name: string,
    locale: string,
    iat: number,
    exp: number
}

interface VerifiedToken {
    isVerified: boolean,
    expired: boolean,
    payload: Payload | UserInfo,
    header: Options
}

interface Payload {
    id: string
}

interface MyUser {
    username: string,
    isVerified: boolean,
    isAdmin: boolean,
    roles: [string],
    password: string,
    email: string,
    unverifiedEmail?: string,
    emailVerified: boolean,
    phoneVerified: boolean,
    unverifiedPhone?: string,
    phoneNumber?: string,
    phoneCarrier?: string,
    phoneCarrierEmail?: string,
    twoPointAuth: boolean,
    twoPointPreference: string,
    resetToken: string,
    phonePin: string,
    verificationToken: string,
    failedLogins: number,
    consent: ConsentScope
}
interface ConsentScope {
consentId: string,
scopes: Array<string>
}

interface IsAdmin {
    isAdmin: boolean
}

interface Midware {
    user: ObjectId,
    token?: string,
    isLoggedIn?: boolean,
    admin?: IsAdmin
}

interface ChangePass {
    oldPassword: string,
    newPassword: string,
    midware: Midware
}

interface ChangePhone {
    newPhone: string,
    midware: Midware,
    newPhoneEmail: string,
    carrier: string
}

interface VerifyPin {
    pin: string
}

interface Pin {
    pin: number,
    midware: Midware
}

interface ChangeEmail {
    newEmail: string,
    midware: Midware
}

interface GoogleRes {
    success: boolean,
    res: string | Tokens
}

interface Tokens {
    id_token: string,
    access_token: string
}

interface ResTokens {
    success: boolean,
    res: {
        id_token: string,
        access_token: string
    }
}

interface UserInfo {
    iss: string,
    azp: string,
    aud: string,
    sub: string,
    email: string,
    email_verified: string,
    at_hash: string,
    name: string,
    picture: string,
    given_name: string,
    family_name: string,
    locale: string,
    iat: number,
    exp: number
}


export const accountSecurityController = {
    requestChangeEmail: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const requestEmailChange: ChangeEmail = req.body;
            const {newEmail, midware: {user}} = requestEmailChange;
            const currentUser = await models.User.findById(user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const pin = `${utils.keys.getPin()}`;
            console.log({pin})
            const hashedPin = utils.keys.encryptPassword(pin);
            currentUser.emailPin = hashedPin; //set an expire time
            currentUser.unverifiedEmail = newEmail;
            //send email containing pin to new 
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err)
        }
    },
    requestChangePhone: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const requestPhoneChange: ChangePhone = req.body;
            const {newPhone, newPhoneEmail, carrier, midware: {user}} = requestPhoneChange;
            const currentUser = await models.User.findById(user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const pin = `${utils.keys.getPin()}`;
            const hashedPin = utils.keys.encryptPassword(pin);
            console.log({pin})
            currentUser.phonePin = hashedPin; //set an expire time
            currentUser.unverifiedPhone = newPhone+';'+newPhoneEmail+';'+carrier;
            //send email containing pin to new 
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err)
        }
    },
    setNewPhone: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const body: Pin = req.body;
            const {pin, midware} = body;
            if(!pin || !midware.user) return next(new ErrorResponse("Missing info", 400));
            const currentUser = await models.User.findById(midware.user).select('+phonePin');
            if(!currentUser || !currentUser.phonePin || !currentUser.unverifiedPhone) return next(new ErrorResponse("Internal Error", 500));
            const match = utils.keys.confirmPassword(`${pin}`, currentUser.phonePin);
            if(!match) return next(new ErrorResponse("Invalid credentials", 500));
            currentUser.phonePin = '';
            const newUserPhone = currentUser.unverifiedPhone.split(';')
            currentUser.phoneNumber = newUserPhone[0];
            currentUser.phoneCarrierEmail = newUserPhone[1];
            currentUser.phoneCarrier = newUserPhone[2]
            currentUser.unverifiedPhone = '';
            currentUser.save();
            res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    setNewEmail: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const body: Pin = req.body;
            const {pin, midware} = body;
            if(!pin || !midware.user) return next(new ErrorResponse("Missing info", 400));
            const currentUser = await models.User.findById(midware.user).select('+emailPin');
            if(!currentUser || !currentUser.emailPin || !currentUser.unverifiedEmail) return next(new ErrorResponse("Internal Error", 500));
            const match = utils.keys.confirmPassword(`${pin}`, currentUser.emailPin);
            if(!match) return next(new ErrorResponse("Invalid credentials", 500));
            currentUser.emailPin = '',
            currentUser.email = currentUser.unverifiedEmail;
            currentUser.unverifiedEmail = '';
            currentUser.save();
            res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    changePassword: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const changePwBody: ChangePass = req.body;
            const {oldPassword, newPassword, midware: {user}} = changePwBody
            const currentUser = await models.User.findById(user).select("+password");
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const match = await utils.keys.confirmPassword(oldPassword, currentUser.password);
            if(!match) return next(new ErrorResponse("Passwords do not match", 401));
            const newHashedPass = await utils.keys.encryptPassword(newPassword);
            currentUser.password = newHashedPass;
            currentUser.passwordSet = true;
            await currentUser.save();
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err)
        }
    },
    verifyAccount: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const body: VerifyPin = req.body;
            const pin = parseInt(body.pin);
            const token = utils.cookies.getCookie(req, 'verify') as string
            if(!pin || !token || token === "") return next(new ErrorResponse("Failed to verify: no token included", 401));
            const info = await utils.jwts.verifyToken(token, "verify") as VerifiedToken;
            const pl = info.payload as Payload;
            if(!info) return next(new ErrorResponse("Failed to verify: no info", 500));
            if(info.expired) return next(new ErrorResponse("You no longer have access!", 404));
            const user  = await models.User.findById(pl.id).select("+verificationToken").select("+verifyPin");
            if(!user || !user.verificationToken || !user.verifyPin) return next(new ErrorResponse("Not found", 404));
            if(token !== user.verificationToken) return next(new ErrorResponse("Failed to verify: not a match!", 404));        
            const match = utils.keys.confirmPassword(`${pin}`, user.verifyPin);
            if(!match) return next(new ErrorResponse("failed to verify code", 401));
            user.isVerified = true;
            user.emailVerified = true;
            user.verificationToken = "";
            user.verifyPin = "";
            user.email = user.unverifiedEmail as string;
            user.unverifiedEmail = ''
            await user.save();
            res.clearCookie("verify");
            res.clearCookie("verifyInitiated")
            return res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    requestResetTempPassword: async (req: Request, res: Response, next: NextFunction) => {
        try{
             //get code from query string
             const code = req.query.code as string;
             console.log("CODE: ", code);
             if(!code){
                 return next(new ErrorResponse("No code sent", 500))
             }         
 
             //get id and access token with code
 
             const googleResponse: GoogleRes | ResTokens = await helpers.google.getGoogleTokens({code});
             if(!googleResponse.success) return next(new ErrorResponse(googleResponse.res&&googleResponse.res!==''&&typeof(googleResponse.res)==='string'?googleResponse.res:"Could not get network", 500))
             const resp = googleResponse.res as Tokens;
             if(!resp.access_token || !resp.id_token) return next(new ErrorResponse("Could not obtain Google tokens", 500));
             const accessToken = resp.access_token;
             const idToken = resp.id_token;
             const user = utils.jwts.verifyToken(idToken, 'google');
             // console.log({user})
             const userInfo = user.payload as UserInfo;
             const exists = await models.User.findOne({email: userInfo.email});
             if(!exists || !exists.googleUser || exists.passwordSet) return next(new ErrorResponse("Cannot reset password", 401));
             const newPass = utils.keys.getSecret(12);
             //email new temp password
             console.log({newPass});
             const hashedNewPass = utils.keys.encryptPassword(newPass);
             exists.password = hashedNewPass;
             await exists.save()
            return res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    resetPin: async(req: Request, res: Response, next: NextFunction) => {
        try{
            const body: Pin = req.body;
            const {pin} = body;
            const token = utils.cookies.getCookie(req, 'forgotPw') as string
            if(!pin || !token) return next(new ErrorResponse("Failed to verify reset: missing information", 402));
            const info = await utils.jwts.verifyToken(token, "forgotPw") as VerifiedToken;
            const pl = info.payload as Payload;
            if(!info.isVerified || info.expired) return next(new ErrorResponse("Failed to verify reset", 401));
            const user = await models.User.findById(pl.id).select('+resetPin').select('+forgotPassToken');
            if(!user || !user.resetPin || user.resetPin === '' || !user.forgotPassToken || user.forgotPassToken !== token) return next(new ErrorResponse("Not verified", 401));
            const hashedPin = user.resetPin;
            const match = await utils.keys.confirmPassword(`${pin}`, hashedPin);
            if(!match) return next(new ErrorResponse("Failed to verify reset: invalid credentials", 401));
            user.resetPin = '';
            user.forgotPassToken = '';
            const resetToken = await utils.jwts.signToken({id:user._id, hostname: req.hostname, type: "resetPw"});
            if(!resetToken.token) return next(new ErrorResponse("Internal error", 500))
            user.resetToken = resetToken.token;
            await user.save();
            res.clearCookie("forgotPw");
            res.clearCookie("forgotPwInitiated")
            res.cookie( 
                "resetPw",
                resetToken.token,
                utils.cookies.setOptions(resetToken.expires)
            )
            res.cookie(
                "resetPwInitiated",
                `true;${resetToken.expires}`,
                utils.cookies.setOptions(resetToken.expires, 'client')
            )
            return res.status(200).json({
                success: true,
                token: resetToken.token
            })
        }
        catch(error){
            next(error)
        }
    },
    resendPin: async(req: Request, res: Response, next: NextFunction) => {
        try{
            const verify = utils.cookies.getCookie(req, 'verify') as string;
            const forgotPw = utils.cookies.getCookie(req, 'forgotPw') as string;
            const login = utils.cookies.getCookie(req, 'login') as string;
            let token;
            let type: 'login' | 'forgotPw' | 'verify' = 'verify';
            if(login) {
                token = login;
                type = 'login'
            }
            if(forgotPw) {
                token = forgotPw;
                type = 'forgotPw'
            }
            if(verify) {
                token = verify;
                type = 'verify'
            }
            if(!token) return next(new ErrorResponse("No access", 401));
            const info = utils.jwts.verifyToken(token, type) as VerifiedToken
            if(!info.isVerified || info.expired ) return next(new ErrorResponse("Not verified", 401));
            const pl = info.payload as Payload;
            if(!pl.id) return next(new ErrorResponse("Not found, no access", 401))
            const user = await models.User.findById(pl.id);
            if(!user) return next(new ErrorResponse("No user found, no access", 401));
            const pin = utils.keys.getPin();
            console.log({pin})
            const hashedPin = utils.keys.encryptPassword(`${pin}`);
            if(type === 'verify') user.verifyPin = hashedPin;
            if(type === 'login') user.loginPin = hashedPin;
            if(type === 'forgotPw') user.resetPin = hashedPin;
            const newToken = utils.jwts.signToken({id: user._id, hostname: req.hostname, type})
            user.verificationToken = newToken.token;
            await user.save();
            res.cookie(
                type, 
                newToken.token,
                utils.cookies.setOptions(newToken.expires)
            )
            res.cookie(
                `${type}Initiated`,
                `true;${newToken.expires}`,
                utils.cookies.setOptions(newToken.expires, 'client')
            )
            res.status(200).json({
                success: true,
            })
        }
        catch(err){
            next(err)
        }
    },
    loginPin: async(req: Request, res: Response, next: NextFunction) => {
        try{
            const body: Pin = req.body;
            const {pin} = body;
            const token = utils.cookies.getCookie(req, 'login')
            if(!pin || !token) return next(new ErrorResponse("Failed to login: missing information", 402));
            const info = await utils.jwts.verifyToken(token as string, "login") as VerifiedToken;
            const pl = info.payload as Payload;
            if(!info.isVerified || info.expired) return next(new ErrorResponse("Failed to verify reset", 401));
            const user = await models.User.findById(pl.id).select('+loginPin').select('+loginToken');
            if(!user || !user.loginPin || user.loginPin === '' || !user.loginToken || user.loginToken !== token) return next(new ErrorResponse("Not verified", 401));
            const hashedPin = user.loginPin;
            const match = await utils.keys.confirmPassword(`${pin}`, hashedPin);
            if(!match) return next(new ErrorResponse("Failed to login: invalid credentials", 401));
            user.loginPin = '';
            user.loginToken = '';
            await user.save();

            //set cookies to login in user
            const aType = "access"
            const rType = "refresh"

            //sign tokens
            const refToken = await utils.jwts.signToken({id: user._id, hostname: req.hostname, ip: req.ip, type: rType});
            const accToken = await utils.jwts.signToken({id: user._id, hostname: req.hostname, type: aType});
            await helpers.cache.setCache(user._id, refToken.token, refToken.expires)
            res.clearCookie("login");
            res.clearCookie("loginInitiated")
            res.cookie(
                rType,
                refToken.token,
                utils.cookies.setOptions(refToken.expires)
            )
            res.cookie(
                aType,
                accToken.token,
                utils.cookies.setOptions(accToken.expires)
            )
            res.cookie(
                "hasCredentials", 
                `true;${accToken.expires}`,
                utils.cookies.setOptions(accToken.expires, 'client')
            )
            console.log("l", user._id)
            return res.status(201).json({
                user: {username: user.username, roles: user.roles, email: user.email, phoneNumber: user.phoneNumber?? '', phoneEmail: user.phoneCarrierEmail?? '', phoneVerified: user.phoneVerified?? false, contactPreference: user.contactPreference, twoPointAuth: user.twoPointAuth, twoPointPreference: user.twoPointPreference, emailVerified: user.emailVerified},
                isAuth: true,
                isAdmin: user.isAdmin,
                success: true
            })
        }
        catch(error){
            next(error)
        }
    }
}