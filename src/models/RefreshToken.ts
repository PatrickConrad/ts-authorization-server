import mongoose, { ObjectId } from 'mongoose';

interface IRefresh {
        userId: ObjectId
        token: string,
        expires: number,
}

interface IRefreshMod extends IRefresh, mongoose.Document{}

const refreshSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Types.ObjectId,
        required: [true, "must have user Id"],
    },
    token: {
        type: String,
        required: [true, "must have a token"],
    },
    expires: {
        type: Number,
    }
});

export const RefreshToken = mongoose.model<IRefreshMod>("RefreshToken", refreshSchema);

