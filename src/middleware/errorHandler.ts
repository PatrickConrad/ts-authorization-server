import ErrorResponse from '../utils/errorResponse';
import { Response } from 'express';

export const errorHandler = (err: ErrorResponse, res:Response) => {
    console.log(err.message);
    let error = {...err};
    error.message = err.message;

    console.log({ status: error.statusCode});
    res.status(error.statusCode || 500).json({
        success: false,
        error: {
            msg: error.message || "Server Error",
            customMsg: error.customMsg || 'There was a problem', 
            status: error.statusCode || 500
        }
    })
}

