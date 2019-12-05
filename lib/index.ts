import assert from "assert";
import express from "express";
import { use } from "express-requesthandler";
import firebase from "firebase-admin";
import { Document, Model } from "mongoose";

interface IAuthOptions {
    firebaseApp?: firebase.app.App;
    userModel: Model<IUser & Document>;
    userUid?: string;
    userConstructor?: (uid: string, info: firebase.auth.UserRecord) => IUser & Document;
    keys: Record<string, IKey>;
}

interface IUser {
    claims?: Record<string, boolean>;
}

interface IKey {
    privateKey?: Buffer;
    publicKey: Buffer;
    algorithm: string;
    subject?: string;
    provider: string;
    userUid?: string;
    expiresIn?: number;
}

export class AuthRoute {
    public static router = express.Router();

    public static authOptions: IAuthOptions;

    /** Initializes the authentication module */
    public static initializeAuth(options: IAuthOptions) {
        this.authOptions = options;
    }

    /** Verifies a token and returns the corresponding user */
    @use(true)
    public static async verifyToken(authorization: string): Promise<{ user: IUser & Document, provider: any }> {
        const [authType, idToken] = authorization.split(" ");

        // Validate the format of the authorization header
        assert(authType === "Bearer" && idToken, "The authorization header has an invalid format");

        // Verify the validity of the token
        const payload = await firebase.auth(this.authOptions.firebaseApp).verifyIdToken(idToken);

        if (payload.expiresIn) {
            assert(payload.expiresIn > new Date(), "The token has expired");
        }

        // Find and update the user in the database
        const User = this.authOptions.userModel as Model<IUser & Document>;
        let user = await User.findOne({ [this.authOptions.userUid || "uid"]: payload.uid });

        if (!user) {
            const info = await firebase.auth().getUser(payload.uid);
            Object.assign(info, payload);
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
