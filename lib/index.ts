import assert from "assert";
import express from "express";
import { use } from "express-requesthandler";
import firebase from "firebase-admin";
import fs from "fs";
import { Document, Model } from "mongoose";

interface IUser {
    claims?: Record<string, boolean>;
}

export class AuthRoute {
    public static router = express.Router();

    public static authOptions: Record<string, any> = {};
    public static publicKey?: Buffer;
    public static privateKey?: Buffer;

    /** Initializes the authentication module */
    public static initializeAuth(options: Record<string, any>) {
        Object.assign(this.authOptions, options);

        this.publicKey = this.authOptions.publicKey ? fs.readFileSync(this.authOptions.publicKey) : undefined;
        this.privateKey = this.authOptions.publicKey ? fs.readFileSync(this.authOptions.privateKey) : undefined;
    }

    /** Verifies a token and returns the corresponding user */
    @use(true)
    public static async verifyToken(authorization: string): Promise<{ user: IUser & Document, provider: any }> {
        assert(this.authOptions.userModel, "The userModel parameter is required in the authentication module options");
        const [authType, idToken] = authorization.split(" ");

        // Validate the format of the authorization header
        assert(authType === "Bearer" && idToken, "The authorization header has an invalid format");

        // Verify the validity of the token
        const payload = await firebase.auth(this.authOptions.firebaseApp).verifyIdToken(idToken);

        // Find and update the user in the database
        const User = this.authOptions.userModel as Model<IUser & Document>;
        let user = await User.findOne({ [this.authOptions.userUid || "uid"]: payload.uid });

        if (!user) {
            const info = await firebase.auth().getUser(payload.uid);
            user = this.authOptions.userConstructor ? this.authOptions.userConstructor(payload.uid, info) as IUser & Document : new User({ [this.authOptions.userUid || "uid"]: payload.uid, info });
            await user.save();
        }

        // Check for additional claims
        if (user.claims) {
            for (const key in user.claims) {
                if (user.claims[key]) {
                    assert(payload[key], `The user is required to log in with the additional claim of ${key}`);
                }
            }
        }

        return { user, provider: payload.provider ? payload.provider : payload.firebase.sign_in_provider };
    }
}

export default AuthRoute.router;
