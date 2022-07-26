import ErrorResponse from '../utils/errorResponse';
import { NextFunction, Request, Response } from 'express';

export const errorHandler = (err: ErrorResponse, req: Request, res:Response, next: NextFunction) => {
    let error = {...err};
    error.message = err.message;

    res.status(error.statusCode || 500).json({
        success: false,
        error: {
            msg: error.message || "Server Error",
            customMsg: error.customMsg || 'There was a problem', 
            status: error.statusCode || 500
        }
    })
}

