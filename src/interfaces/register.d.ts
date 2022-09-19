import { NextFunction, Request, Response } from "express"
import {Document} from "mongoose"

interface RegisterUser {
    email: string,
    username: string,
    password: string
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
    verificationToken: string,
    orgVerificationToken: string,
    loginToken: string,
    resetPin: string,
    phonePin: string,
    loginPin: string,
    verifyPin: string,
    orgVerifyPin: string,
    failedLogins: number,
    contactPreference: string,
    googleUser?: boolean,
    passwordSet: boolean,
    consents: string[]
}

export interface TwoPointMidware {
    user: IUser,
    type: PinTypes
}

type PinTypes = 'login' | 'verify' | 'forgot_password' | 'organization_verify'

type Req = Request
type Nxt = NextFunction
type Res = Response

export interface IUser extends MyUser, Document{}

export {RegisterUser}