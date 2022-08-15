// import { proxyRequest } from './../helpers/proxyRequest';
import { VerifiedToken } from './../types/imports';
import mongoose, { ObjectId } from 'mongoose';
import { NextFunction, Request, Response } from "express"
import {RegisterUser} from '../interfaces/register'
import ErrorResponse from '../utils/errorResponse'
import {utils} from '../utils'
import {models} from '../models';
import {helpers} from '../helpers'
import path from 'path'
import axios from 'axios'
import qs from 'qs'
import http from 'http';
import url from 'url';

interface Payload {
    id: ObjectId
}

type Scope = 'authorization' | 'email' | 'phone' | 'profile'

interface ConsentScope {
    id: string,
    scopes: Scope[]
}

interface ForgotPass {
    identifier: string,
    contactPreference?: string
}

interface LoginUser {
    identifier: string,
    password: string
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

export const authController = {
    login: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const u: LoginUser = req.body.user;
            const user = await models.User.findOne({username: u.identifier}).select("+password") || await models.User.findOne({email: u.identifier}).select("+password") || await models.User.findOne({phoneNumber: u.identifier}).select("+password");
            if(!user){
                return next(new ErrorResponse("Invalid Credentials", 401))
            }
            const hashedPassword = user.password;
            const match = await utils.keys.confirmPassword(u.password, hashedPassword);
            if(!match){
                console.log("Don't match")
                user.failedLogins = user.failedLogins + 1;
                await user.save();
                if(user.failedLogins >= 6) return next(new ErrorResponse("Too many attempts", 401));
                return next(new ErrorResponse("Invalid credentials", 401));
            }
            if(!user.isVerified ) {
                const verifyToken = utils.jwts.signToken({id: user._id, hostname: req.hostname, type: 'verify'});
                if(!verifyToken.token) return next(new ErrorResponse('Internal Error', 500));
                console.log({verificationToken: verifyToken.token});
                user.verificationToken = verifyToken.token;
                const pin = utils.keys.getPin();
                //email pin to user
                console.log({pin});
                const hashedPin = utils.keys.encryptPassword(`${pin}`);
                user.verifyPin = hashedPin;
                await user.save();
                res.cookie(
                    "verify",
                    verifyToken.token,
                    utils.cookies.setOptions(verifyToken.expires)
                )
                res.cookie(
                    "verifyInitiated",
                    `true;${verifyToken.expires}`,
                    utils.cookies.setOptions(verifyToken.expires, 'client')
                )
                return res.status(200).json({
                    success: true,
                    type: 'verify',
                    message: 'Please verify your account by providing the pin that was sent to your email'
                })
            }
            if(!user.twoPointAuth){
                console.log("dont have two point")
                user.failedLogins = 0;
                await user.save();
                const {_id} = user;
                const aType = "access"
                const rType = "refresh"
                const refToken = await utils.jwts.signToken({id: _id, hostname: req.hostname, ip: req.ip, type: rType});
                const accToken = await utils.jwts.signToken({id: _id, hostname: req.hostname, type: aType});
                await helpers.cache.setCache(_id, refToken.token, refToken.expires)
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
                    `true;${accToken.expires};${user.username}`,
                    utils.cookies.setOptions(accToken.expires, 'client')
                )
                res.cookie(
                    "accessggg", 
                    `true;${accToken.expires};${_id}`,
                    utils.cookies.setOptions(accToken.expires, 'client')
                )
                return res.status(201).json({
                    user: {id: user._id, username: user.username, roles: user.roles, email: user.email, phoneNumber: user.phoneNumber?? '', phoneEmail: user.phoneCarrierEmail?? '', phoneVerified: user.phoneVerified?? false},
                    isAuth: true,
                    twoPoinAuth: false,
                    isAdmin: user.isAdmin,
                    success: true
                })
            }
            console.log("Has two point")
            const getPin = utils.keys.getPin();
            const pin = `${getPin}`;
            const hashedPin = await utils.keys.encryptPassword(pin);
            user.loginPin = hashedPin;
            console.log("pin", pin)
            const loginToken = await utils.jwts.signToken({id: user._id, hostname: req.hostname, type: 'login'});
            if(!loginToken.token) return next(new ErrorResponse("Error signing", 500));
            console.log("EmailToken: ",loginToken);
            user.loginToken = loginToken.token; 
            await user.save();
            res.cookie(
                "login", 
                loginToken.token,
                utils.cookies.setOptions(loginToken.expires)
            )
            res.cookie(
                "loginInitiated",
                `true;${loginToken.expires}`,
                utils.cookies.setOptions(loginToken.expires, 'client')
            )
            if(user.twoPointPreference === 'email' || !user.phoneNumber){
                // const isSent = await sendMessage('email', user.email, "twoPoint", pin);
                // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
                return res.status(200).json({
                    success: true,
                    token: loginToken,
                    twoPointAuth: true,
                    type: 'email'
                })
            }
            const combinedEmail = user.phoneNumber + user.phoneCarrierEmail;
            // const isSent = await sendMessage("phone", combinedEmail, "verify", pin);
            // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
            return res.status(201).json({
                success: true,
                twoPointAuth: true,
                type: 'phone'
            })
        }
        catch(err){
            next(err)
        }
    },
    register: async (req: Request, res: Response, next: NextFunction) => {
        try{
            console.log(req.body)
            const regUser: RegisterUser = req.body.user;
            const {email, username, password} = regUser;
            if(!email || !username || !password){
                return next(new ErrorResponse('Please enter all required information!', 400));
            }
            const usernameIsEmail = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(username)
            console.log({usernameIsEmail})
            if(usernameIsEmail && username !== email) return next(new ErrorResponse("If using an email as a username please make sure it matches you email being used", 400));
            console.log('testing', req.body)
            const exists = await models.User.findOne({username}) || await models.User.findOne({email})
            if(exists ) return next(new ErrorResponse("Username or email already in use.", 400));
            const hashPassword = await utils.keys.encryptPassword(password);
            const pin = `${utils.keys.getPin()}`;
            console.log({usePin: pin})
            const hashedPin = utils.keys.encryptPassword(pin);

            const user = new models.User({
                username,
                password: hashPassword,
                email,
                unverifiedEmail: email,
                verifyPin: hashedPin
            })
            const verificationToken = await utils.jwts.signToken({type: 'verify', id: user._id, hostname: req.hostname});    
            if(!verificationToken.token) return next(new ErrorResponse("Error verifying email", 500));
            // const isSent = await sendMessage('email', email, "verify", link);
            // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
            user.verificationToken = verificationToken.token;
            await user.save();
            res.cookie(
                "verify", 
                verificationToken.token,
                utils.cookies.setOptions(verificationToken.expires)
            )
            res.cookie(
                "verifyInitiated",
                `true;${verificationToken.expires}`,
                utils.cookies.setOptions(verificationToken.expires, 'client')
            )
            res.status(200).json({
                success: true,
            })
        }
        catch(err){
            next(err);
        }        
    },
    logout: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const refToken = utils.cookies.getCookie(req, 'refresh');
            await res.clearCookie('refresh');
            await res.clearCookie('access');
            await res.clearCookie('hasCredentials');
            await helpers.cache.clearCache(refToken as string);
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    updateRefresh: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const newRefreshToken = await utils.jwts.signToken({id: req.body.midware.user, hostname: req.hostname, type: "refresh"});
            const newAccessToken = await utils.jwts.signToken({id: req.body.midware.user, hostname: req.hostname, type: "access"});
            if(!newRefreshToken.token || !newAccessToken.token) return next(new ErrorResponse("Invalid Credentials", 401));
            await helpers.cache.setCache(req.body.midware.user, newRefreshToken.token, newRefreshToken.expires);
            await helpers.cache.clearCache(req.body.midware.token);
            const midware: Midware = req.body.midware;
            const currentUser = await models.User.findById(midware.user);
            if(!currentUser) return next(new ErrorResponse("Invalid Credentials", 401))     
            res.cookie(
                "refresh", 
                newRefreshToken,
                utils.cookies.setOptions(newRefreshToken.expires)
            )
            res.cookie(
                "access", 
                newAccessToken,
                utils.cookies.setOptions(newAccessToken.expires)
            )
            res.cookie(
                "hasCredentials", 
                `true;${newAccessToken.expires}`,
                utils.cookies.setOptions(newAccessToken.expires, "client")
            )
            console.log("currID", currentUser._id)
            res.status(200).json({
                success: true,
                user: {id: currentUser._id, username: currentUser.username, roles: currentUser.roles},
                isAuth: true,
                isAdmin: currentUser.isAdmin
            })
        }
        catch(err){
            next(err)
        }
    },
    updateAccess: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const newAccessToken = await utils.jwts.signToken({id: req.body.midware.user, hostname: req.hostname, type: "access"});
            if(!newAccessToken.token) return next(new ErrorResponse("Invalid Credentials", 401));
            const midware: Midware = req.body.midware;
            const currentUser = await models.User.findById(midware.user)
            if(!currentUser) return next(new ErrorResponse("Invalid Credentials", 401)) 
            res.cookie(
                "access", 
                newAccessToken.token,
                utils.cookies.setOptions(newAccessToken.expires)
            )
            res.cookie(
                "hasCredentials", 
                `true;${newAccessToken.expires}`,
                utils.cookies.setOptions(newAccessToken.expires, "client")
            )
            console.log("currID", currentUser._id)
            res.status(200).json({
                success: true,
                user: {id: currentUser._id, username: currentUser.username, roles: currentUser.roles, email: currentUser.email, phoneNumber: currentUser.phoneNumber?? '', phoneEmail: currentUser.phoneCarrierEmail?? ''},
                isAuth: true,
                isAdmin: currentUser.isAdmin
            })     
        }
        catch(err){
            next(err);
        }
    },
    resetPassword:  async (req: Request, res: Response, next: NextFunction) => {
        try{
            const token = utils.cookies.getCookie(req, 'resetPw') as string
            console.log("token", token)
            const newPassword: string = req.body.newPassword;
            if(!token || !newPassword) return next(new ErrorResponse("Failed to reset: missing information", 401));
            const info = await utils.jwts.verifyToken(token, "resetPW");
            const pl = info.payload as Payload;
            if(!info.isVerified || info.expired) return next(new ErrorResponse("Failed to reset: no info", 400));
            const user = await models.User.findById(pl.id).select("+password").select('+resetToken');
            console.log(user)
            if(!user || !user.resetToken || user.resetToken === '' || user.resetToken !== token) return next(new ErrorResponse("No access", 401));
            const hashPassword = await utils.keys.encryptPassword(newPassword);
            user.password = hashPassword;
            user.resetToken = '';
            await user.save();
            res.clearCookie("resetPw");
            res.clearCookie("resetPwInitiated");
            return res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    forgotPassword:  async (req: Request, res: Response, next: NextFunction) => {
        try{
            const body: ForgotPass = req.body;
            const {identifier, contactPreference} = body;
            const user = await models.User.findOne({username: identifier}) || await models.User.findOne({email: identifier}) || await models.User.findOne({phoneNumber: identifier});
            if(!user) return next(new ErrorResponse("User not found", 404));
            const contactType = !contactPreference ? user.contactPreference : contactPreference;
            const pin = `${utils.keys.getPin()}`;
            console.log({pin})
            const hashedPin = await utils.keys.encryptPassword(pin);
            const pinToken = await utils.jwts.signToken({id: user._id, hostname: req.hostname, type: 'forgotPw'});
            console.log("resetTok", pinToken.token);
            user.forgotPassToken = pinToken.token;
            user.resetPin = hashedPin;
            res.cookie(
                "forgotPw", 
                pinToken.token,
                utils.cookies.setOptions(pinToken.expires)
            )
            res.cookie(
                "forgotPwInitiated",
                `true;${pinToken.expires}`,
                utils.cookies.setOptions(pinToken.expires, 'client')
            )
            await user.save();
            if(contactType === 'email' || !user.phoneVerified){
                // await sendMessage('email', user.email, "reset", link);
                return res.status(200).json({
                    success: true,
                    type: 'email'
                })
            }
            const combinedEmail = user.phoneNumber as string + user.phoneCarrierEmail as string;
            // await sendMessage('phone', combinedEmail, 'reset', pin);
            console.log("Reset Pin: " + pin)
            res.status(200).json({
                success: true,
                type: "phone"
            })     
        }
        catch(err){
            next(err);
        }
    },
    goToGoogle: (req: Request, res: Response, next: NextFunction) => {
        try{
            const urlToGoogleOauth: string = helpers.google.getGoogleAuthUrl();
            console.log({urlToGoogleOauth})
            return res.status(201).json({
                success: true,
                url: urlToGoogleOauth
            })
        }
        catch(err){
            next(err)
        }
    },
    googleAuth: async (req: Request, res: Response, next: NextFunction) => {
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
            console.log({exists})
            if(exists && !exists.isVerified){
                const verifyToken = utils.jwts.signToken({id: exists._id, hostname: req.hostname, type: 'verify'});
                if(!verifyToken.token) return next(new ErrorResponse('Internal Error', 500));
                console.log({verificationToken: verifyToken.token});
                exists.verificationToken = verifyToken.token;
                const pin = utils.keys.getPin();
                console.log({pin});
                const hashedPin = utils.keys.encryptPassword(`${pin}`);
                exists.verifyPin = hashedPin;
                await exists.save();
                res.cookie(
                    "verify",
                    verifyToken.token,
                    utils.cookies.setOptions(verifyToken.expires)
                )
                res.cookie(
                    "verifyInitiated",
                    `true;${verifyToken.expires}`,
                    utils.cookies.setOptions(verifyToken.expires, 'client')
                )
                return res.redirect('http://localhost:3000/verify/email')

            }
            if(exists && exists.twoPointAuth){
                const getPin = utils.keys.getPin();
                const pin = `${getPin}`;
                const hashedPin = await utils.keys.encryptPassword(pin);
                exists.loginPin = hashedPin;
                console.log("pin", pin)
                const loginToken = await utils.jwts.signToken({id: exists._id, hostname: req.hostname, type: 'login'});
                if(!loginToken.token) return next(new ErrorResponse("Error signing", 500));
                console.log("EmailToken: ",loginToken);
                exists.loginToken =   await loginToken.token; 
                await exists.save();
                
                res.cookie(
                    "login", 
                    loginToken.token,
                    utils.cookies.setOptions(loginToken.expires)
                )
                res.cookie(
                    "loginInitiated", 
                    `true;${loginToken.expires}`,
                    utils.cookies.setOptions(loginToken.expires, 'client')
                )
                if(exists.twoPointPreference === 'email' || exists.phoneNumber == undefined|| !exists.phoneCarrierEmail){
                    // const isSent = await sendMessage('email', user.email, "twoPoint", pin);
                    // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));

                    return res.redirect('http://localhost:3000/auth/google/verify/email')

                }
                const combinedEmail = exists.phoneNumber as string + exists.phoneCarrierEmail as string;
                // const isSent = await sendMessage("phone", combinedEmail, "verify", pin);
                // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
               
                return res.redirect('http://localhost:3000/auth/google/verify/phone')
             
            }
            if(exists && !exists.twoPointAuth){
                const aType = "access"
                const rType = "refresh"
                const refToken = await utils.jwts.signToken({id: exists._id, hostname: req.hostname, ip: req.ip, type: rType});
                const accToken = await utils.jwts.signToken({id: exists._id, hostname: req.hostname, type: aType});
                await helpers.cache.setCache(exists._id, refToken.token, refToken.expires)
                
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
                console.log("l", exists._id)
                return res.redirect('http://localhost:3000/my-account')
            }

            //add sign up logic

                //send this temp password to user email
            const tempPassword = utils.keys.getSecret(10);
                //send via email
                console.log({tempPassword})

            const hashedTemp = utils.keys.encryptPassword(tempPassword)

            const newUser = new models.User({
                email: userInfo.email,
                password: hashedTemp,
                username: userInfo.email,
                emailVerified: userInfo.email_verified,
                passwordSet: false,
                googleUser: true
            })


            if(!userInfo.email_verified){
                const pin = utils.keys.getPin();
                console.log({pin})
                const hashedPin = utils.keys.encryptPassword(`${pin}`)
                newUser.verifyPin = hashedPin;
                newUser.unverifiedEmail = userInfo.email;

                //send pin to user at unverified Email;
                
                const verificationToken = await utils.jwts.signToken({type: 'verify', id: newUser._id, hostname: req.hostname});    
                if(!verificationToken.token) return next(new ErrorResponse("Error verifying email", 500));
                // const isSent = await sendMessage('email', email, "verify", link);
                // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
                newUser.verificationToken = verificationToken.token;

                await newUser.save();

                res.cookie(
                    "verify", 
                    verificationToken.token,
                    utils.cookies.setOptions(verificationToken.expires)
                )
                res.cookie(
                    "verifyInitiated", 
                    `true;${verificationToken.expires}`,
                    utils.cookies.setOptions(verificationToken.expires, 'client')
                )
                return res.redirect('http://localhost:3000/auth/google/verify/email')
            }
            newUser.isVerified = true;
            await newUser.save();

            const aType = "access"
            const rType = "refresh"
            const refToken = await utils.jwts.signToken({id: newUser._id, hostname: req.hostname, ip: req.ip, type: rType});
            const accToken = await utils.jwts.signToken({id: newUser._id, hostname: req.hostname, type: aType});
            await helpers.cache.setCache( newUser._id, refToken.token, refToken.expires)
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
            return res.redirect('http://localhost:3000/my-account')
        }
        catch(err){
            next(err)
        }
    },
    organizationAuthorization: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const user = req.body.user;
            const orgId = req.query.id as string;
            const exists = await models.User.findOne({email: user.identifier}).select("+password") || await models.User.findOne({phoneNumber: user.identifier}).select("+password") || await models.User.findOne({username: user.identifier}).select("+password")
            if(!exists) return next(new ErrorResponse("User doesn't exist", 404))
            const orgExists = await exists?.consents.find(c=> orgId===c)
            if(!user.consent && !orgExists) return next(new ErrorResponse("Consent is requried for sign up", 404))
            const hasAccess = await utils.cookies.getCookie(req, 'access') as string;
            if(!hasAccess){
                const match = utils.keys.confirmPassword(user.password, exists.password);
                if(!match) return next(new ErrorResponse("User doesn't exist", 404))
                if(!orgExists){
                    exists.consents = [...exists.consents, orgId]
                    await exists.save()
                }
                const data = {
                    id: exists._id,
                    phoneVerified: exists.phoneVerified,
                    emailVerified: exists.emailVerified
                }
                const orgKey = utils.keys.readKey('OrganizationAuthPublicKey', path.join(__dirname, '../../serverKeys/publicKeys'))
                const encrypted = utils.keys.encryptWithPublic(orgKey, JSON.stringify(data));
                console.log({encrypted})
                const redirect = req.query.redirect as string;
                console.log("router", req.query)
                console.log("redirect", req.query.redirect)
                if(!redirect) return next(new ErrorResponse("Must include a authorized redirect url", 400))
                console.log({encrypted}) 
                const clientUrl = `${redirect}?${qs.stringify({code: encrypted})}`
                return res.status(200).json({
                    success: true,
                    clientUrl
                })
            }
            const info = utils.jwts.verifyToken(hasAccess, 'access') as VerifiedToken;
            if(!info || !info.isVerified || info.expired) return next(new ErrorResponse("Cannot verify", 404)) 
            if(!orgExists){
                exists.consents = [...exists.consents, orgId]
                await exists.save()
            }
            const data = {
                id: exists._id,
                phoneVerified: exists.phoneVerified,
                emailVerified: exists.emailVerified
            }
            const orgKey = utils.keys.readKey('OrganizationAuthPublicKey', path.join(__dirname, '../../serverKeys/publicKeys'))
            console.log({orgKey})
            const encrypted = utils.keys.encryptWithPublic(orgKey, JSON.stringify(data));
            console.log({encrypted})
            const redirect = req.query.redirect as string;
            console.log(redirect)
            if(!redirect) return next(new ErrorResponse("Must include a authorized redirect url", 400))
            const clientUrl = `${redirect}?${qs.stringify({code: encrypted})}`
            return res.status(200).json({
                success: true,
                clientUrl
            })
        }
        catch(err){
            next(err)
        }
    },
}