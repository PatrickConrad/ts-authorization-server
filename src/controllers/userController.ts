import { NextFunction, Request, Response } from "express"
import {RegisterUser} from '../interfaces/register'
import ErrorResponse from '../utils/errorResponse'
import {utils} from '../utils'
import {models} from '../models';
import { ObjectId } from "mongoose";

export interface Payload {
    id: string
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

interface ChangePhone {
    newPhone: string,
    midware: Midware,
    newPhoneEmail: string,
    carrier: string
}

interface Pin {
    pin: number,
    midware: Midware
}

interface ChangeEmail {
    newEmail: string,
    midware: Midware
}

interface Username {
    username: string,
    midware: Midware
}

interface SecuritySettings {
    twoPointAuth?: boolean,
    contactPreference?: 'email' | 'phone',
    twoPointPreference?: 'email' | 'phone',
    midware: Midware
}

export const userController = {
    requestChangeEmail: async (req: Request, res: Response, next: NextFunction) => {
        try{
            const requestEmailChange: ChangeEmail = req.body;
            const {newEmail, midware: {user}} = requestEmailChange;
            const exists = await models.User.findOne({email: newEmail});
            if(exists) return next(new ErrorResponse("Cannot set email", 401));
            const currentUser = await models.User.findById(user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const pin = `${utils.keys.getPin()}`;
            const hashedPin = utils.keys.encryptPassword(pin);
            currentUser.emailPin = hashedPin; //set an expire time
            currentUser.unverifiedEmail = newEmail;
            currentUser.emailVerified = false;
            await currentUser.save();
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
            const exists = await models.User.findOne({phoneNumber: newPhone});
            if(exists) return next(new ErrorResponse("Cannot set phone", 401));
            const currentUser = await models.User.findById(user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const pin = `${utils.keys.getPin()}`;
            const hashedPin = utils.keys.encryptPassword(pin);
            currentUser.phonePin = hashedPin; //set an expire time
            currentUser.unverifiedPhone = newPhone+';'+newPhoneEmail+';'+carrier;
            currentUser.phoneVerified = false;
            await currentUser.save()
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
            currentUser.phoneVerified = true;
            await currentUser.save();
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
            currentUser.emailVerified = true
            await currentUser.save();
            res.status(201).json({
                success: true
            })
        }
        catch(err){
            next(err);
        }
    },
    updateUserSecurity: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const body: SecuritySettings = req.body;
            const {twoPointAuth, contactPreference, twoPointPreference, midware} = body;
            if(!midware.user) return next(new ErrorResponse("Missing info", 400));
            const currentUser = await models.User.findById(midware.user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            currentUser.twoPointAuth = twoPointAuth?? currentUser.twoPointAuth;
            currentUser.twoPointPreference = twoPointPreference?? currentUser.twoPointPreference;
            currentUser.contactPreference = contactPreference??currentUser.contactPreference;
            currentUser.save();
            res.status(201).json({
                success: true,
            })
        }
        catch(err){
            next(err);
        }
    },
    updateUsername: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const body: Username = req.body;
            const {username, midware} = body;
            if(!midware.user) return next(new ErrorResponse("Missing info", 400));
            const exists = await models.User.findOne({username});
            if(exists) return next(new ErrorResponse("Can not set username", 401));
            const currentUser = await models.User.findById(midware.user);
            if(!currentUser) return next(new ErrorResponse("Internal Error", 500));
            const usernameIsEmail = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(username)
            if(usernameIsEmail && username !== currentUser.email) return next(new ErrorResponse("If using an email as a username please make sure it matches you email being used", 400));
            currentUser.username = username;
            currentUser.save();
            res.status(201).json({
                success: true,
            })
        }
        catch(err){
            next(err);
        }
    }
}