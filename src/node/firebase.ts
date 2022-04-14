import * as express from "express"
import { App, AppOptions, initializeApp } from "firebase-admin/app"
import { Auth, getAuth, DecodedIdToken } from "firebase-admin/auth"

let app: App | undefined
let auth: Auth | undefined
const cache = new Map<string, { expireDate: Date; user: DecodedIdToken }>()

export const getAppInstance = (options: () => AppOptions): App => {
  if (app === undefined && options === undefined)
    throw new Error("Firebase was not initialized and no credentials were provided.")

  return app === undefined ? (app = initializeApp(options())) : app
}

export const getAuthInstance = (): Auth => {
  if (app === undefined) throw new Error("Firebase was not initialized.")

  return auth === undefined ? (auth = getAuth(app)) : auth
}

export const validateAuthToken = async (token: string, authInstance: Auth): Promise<DecodedIdToken | undefined> => {
  const isExpired = (cache.get(token)?.expireDate || new Date()).getTime() <= new Date().getTime()
  if (!isExpired) return cache.get(token)?.user

  try {
    const user = await authInstance.verifyIdToken(token)
    const expireDate = new Date()

    expireDate.setMinutes(5 + expireDate.getMinutes())
    cache.set(token, { expireDate, user })
    return user
  } catch {
    return undefined
  }
}

export const buildCredentials = (req: express.Request): AppOptions => {
  return {
    apiKey: req.args["firebase-api-key"],
    authDomain: req.args["firebase-auth-domain"],
    projectId: req.args["firebase-project-id"],
    storageBucket: req.args["firebase-storage-bucket"],
    messagingSenderId: req.args["firebase-messaging-sender-id"],
    appId: req.args["firebase-app-id"],
  } as AppOptions
}
