import assert from "assert";
import express from "express";
import { post } from "express-requesthandler";
import firebase from "firebase-admin";
import speakeasy from "speakeasy";

import { AuthRoute } from "../index";

export class TOTPRoute {
    public static router = express.Router();

    /** Signs in the user using a TOTP token and a Firebase idToken */
    @post()
    public static async signInWithTOTP(token: string, idToken: string): Promise<string> {
        // Verify the validity of the token from Firebase
        const { user, provider } = await AuthRoute.verifyToken("Bearer " + idToken) as any;
        assert(user.tfaSecret, "The user is not signed up for two factor authentication");

        // Verify the validity of the token for two factor authentication
        assert(speakeasy.totp.verify({
            secret: user.tfaSecret!,
            encoding: "base32",
            window: 3,
            token
        }), "The token used for two factor authentication was not valid");

        // Add tfa claim
        user.claims = user.claims || {};

        if (!user.claims.tfa) {
            user.claims.tfa = true;
            user.markModified("claims");
            await user.save();
        }

        // Create a custom Firebase token
        return firebase.auth().createCustomToken((user as any)[AuthRoute.authOptions.userUid || "uid"], { provider, tfa: true });
    }

    /** Signs up the user for signing in with TOTP and returns an otp url */
    @post()
    public static async signUpForTOTP(idToken: string): Promise<string> {
        // Verify the validity of the token from Firebase
        const { user } = await AuthRoute.verifyToken("Bearer " + idToken) as any;

        if (!user.tfaSecret) {
            // Generate a TOTP secret
            const secret = speakeasy.generateSecret();
            user.tfaSecret = secret.base32;
            await user.save();

            return secret.otpauth_url!;
        } else {
            return speakeasy.otpauthURL({ secret: user.tfaSecret, label: "" });
        }
    }
}

export default TOTPRoute.router;
