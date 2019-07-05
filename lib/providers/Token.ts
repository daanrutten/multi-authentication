import assert from "assert";
import express from "express";
import { post } from "express-requesthandler";
import jwt from "jsonwebtoken";

import { AuthConfig } from "../Auth";

export class TokenRoute {
    public static router = express.Router();

    /** Signs in the user using a token obtained before */
    @post()
    public static async signInWithToken(token: string) {
        assert(AuthConfig.publicKey, "The publicKey parameter is required in the authentication module options");

        // Verify the validity of the token
        const payload = jwt.verify(token, AuthConfig.publicKey!, { algorithms: ["RS256"], subject: "token:loginToken" }) as { uid: string, info: string };

        // Sign in the user
        return AuthConfig.signIn("token:" + payload.uid, payload.info, "token:loginToken");
    }

    /** Obtains a token for signing in a user */
    public static async obtainToken(uid: string, info: any): Promise<string> {
        assert(AuthConfig.privateKey, "The privateKey parameter is required in the authentication module options");

        // Generate the login token
        const loginToken = jwt.sign({ uid, info }, AuthConfig.privateKey!, { algorithm: "RS256", subject: "token:loginToken" });
        return loginToken;
    }
}

export default TokenRoute.router;
