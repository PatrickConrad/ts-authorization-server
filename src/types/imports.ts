import { ObjectId } from "mongoose"

export interface VerifiedToken {
    isVerified: boolean,
    expired: boolean,
    payload: Payload | UserInfo,
    header: Options
}

export interface Payload {
    id: string | Object
}

export interface Options {
    alg: string,
    exp: number | string,
    aud?: string,
    sub?: ObjectId | string,
    iss: string,
    tai: number | string
}

export interface UserInfo {
    iss: string,
    azp: string,
    aud: string,
    sub: string,
    email: string,
    email_verified: string,
    at_hash: string,
    name: string,
    picture: string,
    given_name: string,
    family_name: string,
    locale: string,
    iat: number,
    exp: number
}