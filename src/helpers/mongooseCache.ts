import { ObjectId } from "mongoose";
import { models } from "../models";

export const cache = {
    setCache: async (id: ObjectId, token: string, expires: number) => {
        try{
            const tkn = new models.RefreshToken({
                userId: id,
                token,
                expires
            })
            await tkn.save();
            return {access: true, message: "saved"};
        }
        catch(err){
            return {access: false, message: "internal error"}
        }
    },
    getCache: async (token: string) => {
        try{
           const exists = await models.RefreshToken.findOne({token}).select("+userId").select("+expires")
           if(!exists) return {access: false, message: "access not found"}
           if(exists.expires < Date.now()) {
                await models.RefreshToken.findOneAndDelete({token});
                return {access: false, message: "expired"}
           }
           return {access: true, message: exists.userId};
        }
        catch(err){
            return { access: false, message: "internal error"};
        }
    },
    updateCache: async (id: ObjectId, oldToken: string, newToken: string, expires: number) => {
        try{
           const exists = await models.RefreshToken.findOne({token: oldToken}).select("+userId").select("+expires")
           if(!exists) return {access: false, message: "access not found"}
           if(exists.expires < Date.now()) {
                await models.RefreshToken.findOneAndDelete({token: oldToken});
                return {access: false, message: "expired"}
           }
           await models.RefreshToken.findOneAndDelete({token: oldToken});
            const tkn = new models.RefreshToken({
                userId: id,
                token: newToken,
                expires
            })
            await tkn.save();
           return {access: true, message: "user updated"};
        }
        catch(err){
            return { access: false, message: "internal error"};
        }
    },
    clearCache: async (token: string) => {
        try{
            await models.RefreshToken.findOneAndDelete({token})
            return {access: true, message: "message deleted"};
        }
         catch(err){
            return {access: false, message: "internal error"};
         }
    }
}
