import mongoose from 'mongoose';

interface ICarrier {
        carrierName: string,
        carrierEmail: string,
        carrierType?: string,
        approved?: boolean,
        test: Testing
}

interface Testing {
    _id: mongoose.Types.ObjectId | '',
    pin: string,
    token: string
}

interface ICarrierMod extends ICarrier, mongoose.Document{}

const TesterSchema: mongoose.Schema = new mongoose.Schema<Testing>({ _id: mongoose.Types.ObjectId || String, pin: {type: String}, token: {type: String} });

const carrierSchema = new mongoose.Schema({
    carrierName: {
        type: String,
        required: [true, "Please provide a carrier name"],
        lowercase: true
    },
    carrierEmail: {
        type: String,
        required: [true, "Please provide a carrier base email"],
        lowercase: true
    },
    carrierType: {
        type: String,
        lowercase: true,
        default: "sms",
        enum: ['sms', 'mms'],
    },
    approved: {
        type: Boolean,
        default: false,
        select: false
    },
    test: {
        type: TesterSchema,
        select: false,      
    }
});

export const Carrier = mongoose.model<ICarrierMod>("Carrier", carrierSchema);

