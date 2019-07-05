import { AuthConfig, AuthRoute, PreAuthRoute } from "./Auth";

export { IUser } from "./Auth";
export const initializeAuth = AuthConfig.initializeAuth.bind(AuthConfig);
export const preAuthRoute = PreAuthRoute.router;
export const authRoute = AuthRoute.router;
