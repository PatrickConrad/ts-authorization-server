import { authorization } from './authorizationCheck';
import { errorHandler } from "./errorHandler";

export const middleware = {
    errorHandler,
    authorization
}