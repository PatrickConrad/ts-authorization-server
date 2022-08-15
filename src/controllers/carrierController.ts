import { NextFunction, Request, Response } from "express"
import ErrorResponse from '../utils/errorResponse'
import {utils} from '../utils'
import {models} from '../models';
import { ObjectId, Types, Document } from "mongoose";

interface ICarrier {
    carrierName: string,
    carrierEmail: string,
    carrierType?: string,
    approved?: boolean,
    testNum?: string
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

interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: ObjectId | string,
    iss: string,
    tai: number | string
}

interface VerifiedToken {
    isVerified: boolean,
    expired: boolean,
    payload: Payload | UserInfo,
    header: Options
}

interface Payload {
    id: ObjectId
}

interface Midware {
    user: ObjectId,
    token?: string,
    isLoggedIn?: boolean,
    admin?: boolean,
    currentUser?: IUser & {
        _id: Types.ObjectId;
    }
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
        emailPin?: string,
        phoneVerified: boolean,
        unverifiedPhone?: string,
        phoneNumber?: string,
        phoneCarrier?: string,
        phoneCarrierEmail?: string,
        twoPointAuth: boolean,
        twoPointPreference: string,
        resetToken: string,
        forgotPassToken: string,
        loginToken: string,
        resetPin: string,
        phonePin: string,
        loginPin: string,
        verifyPin: string,
        verificationToken: string,
        failedLogins: number,
        contactPreference: string,
        googleUserId?: string,
        passwordSet: boolean,
        consents: [ConsentScope]
}

interface ConsentScope {
    _id: Types.ObjectId
    scopes: Array<string>
}

interface IUser extends MyUser, Document{}

export const carriersController = {
    getAllCarriers: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const carriers = await models.Carrier.find({approved: true})
            if(!carriers) return next(new ErrorResponse("No carriers found", 404))
            console.log(carriers)
            res.status(200).json({
                success: true,
                carriers
            })
        }
        catch(err){
            next(err);
        }
    },
    getCarrier: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const id = req.params.id; 
            const carrier = await models.Carrier.findById(id);
            if(!carrier) return next(new ErrorResponse("No carrier found", 404))
            console.log(carrier)
            res.status(200).json({
                success: true,
                carrier
            })
        }
        catch(err){
            next(err);
        }
    },
    requestAddCarrier: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const midware: Midware = req.body.midware;
            if(!midware.user) return next(new ErrorResponse("No access", 401));
            const newCarrier: ICarrier = req.body.carrier;
            const exists = await models.Carrier.findOne({carrierName: newCarrier.carrierName, carrierEmail: newCarrier.carrierEmail})
            if(exists) return next(new ErrorResponse("Carrier already exists", 404))
            //send test email to confirm password works
            const pin = utils.keys.getPin();
            const hashedPin = utils.keys.encryptPassword(`${pin}`);
            const carrierToken = utils.jwts.signToken({type: 'test_carrier', id: midware.user, hostname: req.hostname})
            if(!carrierToken.token) return next(new ErrorResponse("No token", 500));
            const carrier = new models.Carrier({
                carrierName: newCarrier.carrierName,
                carrierEmail: newCarrier.carrierEmail,
                carrierType: newCarrier.carrierType??'mms',
                test: {
                    _id: midware.user,
                    pin: hashedPin,
                    token: carrierToken.token
                }
            })
            await carrier.save();
            res.cookie(
                "testCarrier", 
                carrierToken.token,
                utils.cookies.setOptions(carrierToken.expires)
            )
            console.log(carrier)
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    addCarrier: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const pin: number = req.body.pin;
            const token = utils.cookies.getCookie(req, "testCarrier");
            if(!token) return next(new ErrorResponse("No token on request", 401));
            const info = utils.jwts.verifyToken(token as string, 'testCarrier') as VerifiedToken;
            if(!info.isVerified || info.expired) return next(new ErrorResponse("Can't access", 401))
            const pl = info.payload as Payload;
            const exists = await models.Carrier.findOne({test: {_id: pl.id}});
            if(!exists || token !== exists.test.token ) return next(new ErrorResponse("Carrier doesn't exists", 404));
            const match = utils.keys.confirmPassword(`${pin}`, exists.test.pin);
            if(!match) return next(new ErrorResponse("Invalid Credentials", 401));
            exists.test = {
                _id: '',
                pin: '',
                token: ''
                }
            exists.approved = true;
            await exists.save();
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    adminAddCarrier: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const midware: Midware = req.body.midware;
            const newCarrier: {carrierName: string, carrierEmail: string, carrierType?: string} = req.body.carrier;
            const exists = await models.Carrier.findOne({carrierName: newCarrier.carrierName, carrierEmail: newCarrier.carrierEmail});
            if(!exists) return next(new ErrorResponse("Carrier already exists", 402));
            const carrier = new models.Carrier({
                carrierName: newCarrier.carrierName,
                carrierEmail: newCarrier.carrierEmail,
                carrierType: newCarrier.carrierType??'mms',
                approved: true
            })
            await carrier.save();
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    deleteCarrier: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const id = req.params.id;
            await models.Carrier.findByIdAndDelete(id)
            res.status(200).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
}