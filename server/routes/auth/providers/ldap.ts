import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { capitalize } from "lodash";
// @ts-expect-error ts-migrate(7016) FIXME: Could not find a declaration file for module 'pass... Remove this comment to see the full error message
import { Strategy as LDAPStrategy } from "passport-ldapauth";
import accountProvisioner from "@server/commands/accountProvisioner";
import env from "@server/env";
import passportMiddleware from "@server/middlewares/passport";
import { getAllowedDomains } from "@server/utils/authentication";
import { StateStore } from "@server/utils/passport";

const router = new Router();
const providerName = "ldap";
const allowedDomains = getAllowedDomains();
const scopes = [];

export const config = {
  name: "LDAP",
  enabled: true,
};

if (true) {
  passport.use(
    new LDAPStrategy(
      {
        server: {
          url: 'ldap://localhost:389',
          searchBase: 'ou=users,dc=yunohost,dc=org',
          searchFilter: '(uid={{username}})',
        },
        passReqToCallback: true,
        store: new StateStore(),
        handleErrorsAsFailures: true,
      },
      // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'req' implicitly has an 'any' type.
      async function (req, user, done) {
        try {
          const domain = 'yunohost.org'
          const subdomain = domain.split(".")[0];
          const teamName = capitalize(subdomain);
          const result = await accountProvisioner({
            ip: req.ip,
            team: {
              name: teamName,
              domain,
              subdomain,
            },
            user: {
              name: user.displayName,
              email: user.email,
              avatarUrl: null,
            },
            authenticationProvider: {
              name: providerName,
              providerId: domain,
            },
            authentication: {
              providerId: user.uid,
              accessToken: null,
              refreshToken: null,
              scopes: [],
            },
          });
          return done(null, result.user, result);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get("ldap",passport.authenticate(providerName));

  router.get("ldap.callback", passportMiddleware(providerName));
}

export default router;