import mongoose from 'mongoose';

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
        googleUser?: boolean,
        passwordSet: boolean,
        consents: string[]
}

interface IUser extends MyUser, mongoose.Document{}

const UserSchema: mongoose.Schema = new mongoose.Schema<MyUser>({
        username: {
            type: String,
            lowercase: true,
            required: [true, "Please provide a username"],
            unique: true
        },
        isVerified: {
            type: Boolean,
            default: false
        }, 
        isAdmin: {
            type: Boolean,
            default: false
        },
        roles: [{
            type: String,
        }],
        password: {
            type: String,
            required: [true, "Please add a password"],
            minlength: 6,
            select: false 
        },    
        email: {
            type: String,
            required: [true, "Please provide an email"],
            lowercase: true,
            unique: true,
            match: [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please provide a valid email"
            ]
        },
        unverifiedEmail: {
            type: String,
            lowercase: true,
            match: [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please provide a valid email"
            ]
        },
        emailVerified: {
            type: Boolean,
            default: false
        },
        phoneVerified: {
            type: Boolean,
            default: false
        },
        unverifiedPhone: {
            type: String,
        },
        phoneNumber: {
            type: String,
            default: ''
        },
        phoneCarrier: {
            type: String,
        },
        phoneCarrierEmail: {
            type: String
        },
        twoPointAuth: {
            type: Boolean,
            default: false
        },   
        twoPointPreference: {
            type: String,
            enum: ['phone', 'email'],
            default: 'email'
        },
        resetToken: {
            type: String,
            default: "",
            select: false 
        },
        forgotPassToken: {
            type: String,
            default: "",
            select: false
        },
        loginToken: {
            type: String,
            default: "",
            select: false
        },
        loginPin: {
            type: String,
            default: '',
            select: false
        },
        resetPin: {
            type: String,
            default: '',
            select: false
        },
        phonePin: {
            type: String,
            default: "",
            select: false
        },
        emailPin: {
            type: String,
            default: "",
            select: false
        },
        verifyPin: {
            type: String,
            default: '',
            select: false
        },
        verificationToken: {
            type: String,
            default: "",
            select: false
        },
        passwordSet: {
            type: Boolean,
            default:true
        },
        failedLogins: {
            type: Number,
            default: 0,
            expires: 30000
        },
        contactPreference: {
            type: String,
            enum: ['email', 'phone'],
            default: 'email'
        },
        googleUser: {
            type: Boolean,
            default: false
        },
        consents: [{
            type: String 
        }]
});

export const User = mongoose.model<IUser>("User", UserSchema);

