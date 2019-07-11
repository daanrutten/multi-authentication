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
        assert(AuthRoute.publicKey, "The publicKey parameter is required in the authentication module options");

        // Verify the validity of the token
        const payload = jwt.verify(token, AuthRoute.publicKey!, { algorithms: ["RS256"], subject: "token:loginToken" }) as { uid: string, info: any };

        // Create a custom Firebase token
        return firebase.auth().createCustomToken("token:" + payload.uid, payload.info);
    }

    /** Obtains a token for signing in a user */
    public static async obtainToken(uid: string): Promise<string> {
        assert(AuthRoute.privateKey, "The privateKey parameter is required in the authentication module options");

        // Generate the login token
        const loginToken = jwt.sign({ uid, info: { provider: "token" } }, AuthRoute.privateKey!, { algorithm: "RS256", subject: "token:loginToken" });
        return loginToken;
    }
}

export default TokenRoute.router;
