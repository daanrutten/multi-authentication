import assert from "assert";
import express from "express";
import { post } from "express-requesthandler";
import firebase from "firebase-admin";
import jwt from "jsonwebtoken";

import { AuthRoute } from "../index";

export class TokenRoute {
    public static router = express.Router();

    /** Signs in the user using a token obtained before */
    @post()
    public static async signInWithToken(token: string): Promise<string> {
        const decoded = jwt.decode(token, { complete: true }) as any;
        assert(decoded.header.kid, "The token should contain a kid");

        const key = AuthRoute.authOptions.keys[decoded.header.kid];
        assert(key, "The kid is not supported by the authentication module");

        // Verify the validity of the token
        const payload = jwt.verify(token, key.publicKey, { algorithms: [key.algorithm], subject: key.subject }) as any;

        const uid = payload[key.userUid || "uid"] as string;
        const info = { provider: key.provider } as any;

        if (key.expiresIn) {
            info.expiresIn = new Date(new Date().getTime() + key.expiresIn);
        }

        // Create a custom Firebase token
        return firebase.auth().createCustomToken(key.provider + ":" + uid, info);
    }

    /** Obtains a token for signing in a user */
    public static async obtainToken(uid: string, kid: string, expiresIn?: string | number): Promise<string> {
        const key = AuthRoute.authOptions.keys[kid];
        assert(key && key.privateKey, "The kid is not supported by the authentication module");

        // Generate the login token
        const loginToken = jwt.sign({ [key.userUid || "uid"]: uid }, key.privateKey!, { algorithm: key.algorithm, keyid: kid, subject: key.subject, expiresIn });
        return loginToken;
    }
}

export default TokenRoute.router;
