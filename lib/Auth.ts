import assert from "assert";
import express from "express";
import { get, use } from "express-requesthandler";
import fs from "fs";
import jwt from "jsonwebtoken";
import { Document, Model } from "mongoose";

export interface IUser {
    uid: string;
    info: any;
}

export class AuthConfig {
    public static authOptions: Record<string, any> = {};
    public static publicKey?: Buffer;
    public static privateKey?: Buffer;

    /** Initializes the authentication module */
    public static initializeAuth(options: Record<string, any>) {
        Object.assign(this.authOptions, options);

        this.publicKey = this.authOptions.publicKey ? fs.readFileSync(this.authOptions.publicKey) : undefined;
        this.privateKey = this.authOptions.publicKey ? fs.readFileSync(this.authOptions.privateKey) : undefined;
    }

    /** Signs in the user using its uid, info and provider */
    public static async signIn(uid: string, info: any, provider: any): Promise<{ resourceToken: string, refreshToken: string }> {
        assert(this.authOptions.userModel && this.privateKey, "The userModel and privateKey parameters are required in the authentication module options");

        // Find and update the user in the database
        const User = this.authOptions.userModel as Model<IUser & Document>;
        let user = await User.findOne({ uid }, { info: 1 });

        if (!user) {
            user = this.authOptions.userConstructor ? this.authOptions.userConstructor(uid, info) as IUser & Document : new User({ uid, info });
            await user.save();
        } else {
            user.info = Object.assign(user.info, info);
            user.markModified("info");
            await user.save();
        }

        // Generate the refresh and resource tokens
        const refreshToken = jwt.sign({ _id: user._id.toHexString(), provider }, this.privateKey!, { algorithm: "RS256", subject: "refreshToken" });
        return { resourceToken: await PreAuthRoute.refreshToken(refreshToken), refreshToken };
    }
}

export class PreAuthRoute {
    public static router = express.Router();

    /** Generates a new resource token */
    @get()
    public static async refreshToken(refreshToken: string): Promise<string> {
        assert(AuthConfig.publicKey, "The publicKey parameter is required in the authentication module options");

        // Verify the validity of the refresh token
        const payload = jwt.verify(refreshToken, AuthConfig.publicKey!, { algorithms: ["RS256"], subject: "refreshToken" }) as { _id: string, provider: any };

        // Generate the resource token
        const resourceToken = jwt.sign({ _id: payload._id, provider: payload.provider }, AuthConfig.privateKey!, { algorithm: "RS256", subject: "resourceToken", expiresIn: "1h" });
        return resourceToken;
    }
}

export class AuthRoute {
    public static router = express.Router();

    /** Verifies a token and returns the corresponding user */
    @use("user")
    public static async verifyToken(authorization: string): Promise<{ user: IUser & Document, provider: any }> {
        assert(AuthConfig.authOptions.userModel && AuthConfig.publicKey, "The userModel and publicKey parameters are required in the authentication module options");
        const [authType, resourceToken] = authorization.split(" ");

        // Validate the format of the authorization header
        assert(authType === "Bearer" && resourceToken, "The authorization header has an invalid format");

        // Verify the validity of the resource token
        const payload = jwt.verify(resourceToken, AuthConfig.publicKey!, { algorithms: ["RS256"], subject: "resourceToken" }) as { _id: string, provider: any };

        // Find the corresponding user
        const User = AuthConfig.authOptions.userModel as Model<IUser & Document>;
        const user = await User.findById(payload._id);

        if (!user) {
            throw new Error("The authenticated user does no longer exist");
        }

        return { user, provider: payload.provider };
    }
}
