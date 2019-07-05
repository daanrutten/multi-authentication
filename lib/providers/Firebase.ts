import express from "express";
import { post } from "express-requesthandler";
import firebase from "firebase-admin";

import { AuthConfig } from "../Auth";

export class FirebaseRoute {
    public static router = express.Router();

    /** Signs in the user using an idToken from Firebase */
    @post()
    public static async signInWithFirebase(idToken: string) {
        // Verify the idToken of firebase
        const user = await firebase.auth(AuthConfig.authOptions.firebaseApp).verifyIdToken(idToken, true);
        const info = await firebase.auth().getUser(user.uid);

        // Sign in the user
        return AuthConfig.signIn(user.uid, info, "firebase:" + user.firebase.sign_in_provider);
    }
}

export default FirebaseRoute.router;
