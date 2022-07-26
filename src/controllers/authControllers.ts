import { NextFunction, Request, Response } from "express"
import {RegisterUser} from '../interfaces/register'
import ErrorResponse from '../utils/errorResponse'
import {utils} from '../utils'
import {models} from '../models';

export const authController = {
    login: async (req: Request, res: Response, next: NextFunction) => {
        try{

        }
        catch(err){

        }
    },
    register: async (req: Request, res: Response, next: NextFunction) => {
            try{
                console.log(req.body)
                const regUser: RegisterUser = req.body;
                const {email, username, password} = regUser;
                if(!email || !username || !password){
                    return next(new ErrorResponse('Please enter all required information!', 400));
                }
                console.log('testing', req.body)
                const exists = await models.User.findOne({username}) || await models.User.findOne({email})
                if(exists) return next(new ErrorResponse("Username or email already in use.", 400));
                const hashPassword = await utils.keys.encryptPassword(password);
                const user = new models.User({
                    username,
                    password: hashPassword,
                    email,
                    unverifiedEmail: email
                })
                const verificationToken = await utils.jwts.signToken({type: 'verify', id: user._id.toString(), hostname: req.hostname});    
                if(!verificationToken) return next(new ErrorResponse("Error verifying email", 500));
                console.log("Host name", req.hostname)
                const link =  `http://localhost:3000/vboms/auth/verify/email/${verificationToken}`
                console.log({link})
                // const isSent = await sendMessage('email', email, "verify", link);
                // if(!isSent) return next(new ErrorResponse("Verification Email not sent", 500));
                user.verificationToken = verificationToken;
                console.log("vToken", verificationToken)
                await user.save();
                console.log(user._id)
                res.status(200).json({
                    status: true,
                    id: user._id 
                })
            }
            catch(err){
                console.log(err)
                next(err);
            }        
    }


}