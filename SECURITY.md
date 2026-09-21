# Security

optimusIssuer holds a signing key. A weakness here is more consequential than
in most components of the OptimusDB deployment, so this file is longer than the
usual template.

## Reporting

Do not open a public issue. Report privately through GitHub's security advisory
form on this repository, or by email to the maintainer listed in the project
metadata. Include what you found, how to reproduce it, and what you think the
impact is.

You will get an acknowledgement within a few working days. Nothing is published
until a fix exists or we agree together that disclosure is appropriate.

## What is in scope

- Anything that allows a credential to be issued without operator approval
- Anything that exposes the private key, including through logs, error
  messages, crash output, or the container filesystem
- Bypassing the operator or admin role checks
- Causing an agent to accept a credential this service did not sign
- A canonicalisation defect that makes signatures forgeable

## What is not in scope

- The absence of instant revocation. This is a documented design property of
  verification that works while partitioned, not a defect.
- Denial of service against this component. It is not on the agent request
  path; an outage blocks onboarding and nothing else.
- Running with `-oidc-issuer=""`. That disables operator authentication,
  is intended for development, and logs a warning on every start.

## Design properties worth knowing before you test

**The key is mounted as a file, never an environment variable.** Environment
variables appear in a pod description, in crash dumps and in child process
environments.

**The service refuses to start on a loose key file.** Mode 0600 or it exits.

**Every credential is verified immediately after signing**, using the same code
path an agent runs, so a canonicalisation defect fails at issuance.

**Two keys, not one.** The root issuer key is offline and signs almost nothing;
the service key does day-to-day work. If the service key is compromised, the
root key marks it inactive and every credential it ever signed stops verifying.
This bounds a compromise of this component but does not prevent it.

## If a key is compromised

1. Use the root key to sign a trust-list record setting the service issuer's
   status to `inactive`, and write it through any agent.
2. Confirm it has replicated: query `kbtrust` on each agent.
3. Generate a new service key, authorise it with the root key, replace the
   Secret, restart the Deployment.
4. Reissue credentials that are still needed.
5. Record what happened in the ceremony document.

Step 1 is the one that matters and takes seconds. Everything after it is
recovery at your own pace.
