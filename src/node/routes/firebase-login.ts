import { Router, Request } from "express"
import { promises as fs } from "fs"
import * as os from "os"
import * as path from "path"
import { CookieKeys } from "../../common/http"
import { rootPath } from "../constants"
import * as firebase from "../firebase"
import { authenticated, getCookieOptions, redirect, replaceTemplates } from "../http"
import { humanPath, sanitizeString, escapeHtml } from "../util"

const getRoot = async (req: Request, error?: Error): Promise<string> => {
  const content = await fs.readFile(path.join(rootPath, "src/browser/pages/firebase-login.html"), "utf8")
  const passwordMsg = `Check the config file at ${humanPath(os.homedir(), req.args.config)} for the allowed emails.`

  return replaceTemplates(
    req,
    content
      .replace(/{{PASSWORD_MSG}}/g, passwordMsg)
      .replace(/{{ERROR}}/, error ? `<div class="error">${escapeHtml(error.message)}</div>` : ""),
  )
}

export const router = Router()

router.use(async (req, res, next) => {
  const to = (typeof req.query.to === "string" && req.query.to) || "/"
  if (await authenticated(req)) {
    return redirect(req, res, to, { to: undefined })
  }
  next()
})

router.get("/", async (req, res) => {
  res.send(await getRoot(req))
})

router.post<{}, string, { token: string; base?: string }, { to?: string }>("/", async (req, res) => {
  const token = sanitizeString(req.body.token)

  try {
    // Check to see if they exceeded their login attempts
    if (!token) {
      throw new Error("Missing token.")
    }

    try {
      firebase.getAppInstance(() => firebase.buildCredentials(req))
      const auth = firebase.getAuthInstance()

      const emails = (req.args["allowed-emails"] || "").split(",")
      const user = await auth.verifyIdToken(token)

      if (!emails.includes(user.email || "")) {
        throw new Error("Unauthorized user.")
      }

      res.cookie(CookieKeys.Token, token, getCookieOptions(req))

      const to = (typeof req.query.to === "string" && req.query.to) || "/"
      return redirect(req, res, to, { to: undefined })
    } catch (e) {
      console.error(e)
    }

    console.error(
      "Failed login attempt",
      JSON.stringify({
        xForwardedFor: req.headers["x-forwarded-for"],
        remoteAddress: req.connection.remoteAddress,
        userAgent: req.headers["user-agent"],
        timestamp: Math.floor(new Date().getTime() / 1000),
      }),
    )

    throw new Error("Invalid token, sign in again.")
  } catch (error: any) {
    const renderedHtml = await getRoot(req, error)
    res.send(renderedHtml)
  }
})
