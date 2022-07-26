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

const ScopeSchema = new mongoose.Schema({ scopeType: { type: String, enum: ['email', 'phone', 'auth'] } });

const UserSchema = new mongoose.Schema<MyUser>({
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
            minlength: 10
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
        phonePin: {
            type: String,
            default: "",
            select: false
        },
        verificationToken: {
            type: String,
            default: "",
            select: false
        },
        failedLogins: {
            type: Number,
            default: 0,
            expires: 30000
        },        
        consent: [{
            clientId: {
                type: String,
            },
            scopes: [{
                type: ScopeSchema
            }]
        }]
});

export const User = mongoose.model<MyUser>("User", UserSchema);

