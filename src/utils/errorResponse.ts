class ErrorResponse extends Error {
    statusCode: number;
    customMsg?: string;
    constructor(message: string, statusCode: number){
        super(message);
        this.statusCode = statusCode;
    }
}

export default ErrorResponse