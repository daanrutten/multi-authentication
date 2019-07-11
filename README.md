The example below shows the intended use of this package. The AuthRoute.initializeAuth function should be called as early as possible to set up the module. It expects a Mongoose model of the user which is used to store the uid and additional info of the user given by the authentication provider. It also expects public and private keys used for verifying and signing JWT tokens respectively. The authRoute is middleware to authenticate a user given a Firebase idToken in the authorization header. The user and the provider variables are then exposed as locals to the next routes.

Each of the providers provides their own routes for obtaining a custom token. This custom token should then be used with the Firebase method signInWithCustomToken to obtain a Firebase idToken.

```typescript
import express from "express";
import firebase from "firebase-admin";
import mongoose from "mongoose";
import authRoute, { AuthRoute } from "multi-authentication";
import tokenRoute from "multi-authentication/providers/Token";
import { prop, Typegoose } from "typegoose";

// Setup mongoose
mongoose.connect(`mongodb://${process.env.DB_HOST || "localhost"}:27017/${process.env.MONGO_DB}`, { useCreateIndex: true, useFindAndModify: false, useNewUrlParser: true });

/** Representation of a user in the database */
class IUser extends Typegoose {
    /** Unique identifier of the user */
    @prop({ unique: true, required: true })
    public uid: string = "";

    /** Additional info about the user given by the authentication provider */
    @prop()
    public info: any;
}

// Retrieve the Mongoose model associated with the schema
const User = new IUser().getModelForClass(IUser, { schemaOptions: { strict: "throw" } });

// Initialize the authentication module
AuthRoute.initializeAuth({
    // The Mongoose model for a user
    userModel: User,
    // The Mongoose key of the model used as uid
    userUid: "uid",
    // A function to construct a user given its uid and info (optional)
    userConstructor: (uid: string, info: any) => new User({ uid, info }),
    // The filename of the public key used for verifying JWT tokens
    publicKey: "id_rsa.pub",
    // The filename of the private key used for signing JWT tokens
    privateKey: "id_rsa",
    // The Firebase app to use for authentication
    firebaseApp: firebase.initializeApp({
        credential: firebase.credential.cert(require(process.env.FIREBASE_CONFIG!)),
        databaseURL: process.env.FIREBASE_URL
    })
});

const app = express();

// The tokenRoute exposes the POST /signInWithToken route
app.use("/public", tokenRoute);
// The authRoute is middleware to ensure a valid authorization header and provides the user and provider as locals
app.use("/auth", authRoute);

// Listen
app.listen(3000, () => {
    console.log(`Listening on port 3000`);
});
```