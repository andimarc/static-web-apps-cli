import { response } from "../../../core";
import crypto from "crypto";
import * as http from "http";
const hashStateGuid = function (guid: string) {
  const hash = crypto.createHmac("sha256", process.env.SALT || "");
  hash.update(guid);
  return hash.digest("hex");
};

const httpTrigger = async function (context: Context, _request: http.IncomingMessage, customAuth?: SWAConfigFileAuth) {
  await Promise.resolve();

  let providerName = context.bindingData?.provider?.toLowerCase() || "";
  if (providerName === "aad") {
    providerName = "azureActiveDirectory";
  }

  let provider:
    | MicrosoftEntraIdV1AuthIdentityProvider
    | MicrosoftEntraIdV2AuthIdentityProvider
    | AppleAuthIdentityProvider
    | FacebookAuthIdentityProvider
    | GithubAuthIdentityProvider
    | GoogleAuthIdentityProvider
    | TwitterAuthIdentityProvider
    | undefined;

  if (
    providerName === "azureActiveDirectory" ||
    providerName === "github" ||
    providerName === "twitter" ||
    providerName === "google" ||
    providerName === "facebook"
  ) {
    provider = customAuth?.identityProviders?.[providerName];
  }

  if (!provider) {
    context.res = response({
      context,
      status: 404,
      body: `Provider ${providerName} not found`,
    });
    return;
  }

  if (providerName === "google") {
    const clientIdSettingName = customAuth?.identityProviders?.google?.registration?.clientIdSettingName;

    if (!clientIdSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientIdSettingName not found for Google provider`,
      });
      return;
    }

    const clientId = process.env[clientIdSettingName];

    if (!clientId) {
      context.res = response({
        context,
        status: 404,
        body: `ClientId not found for Google provider`,
      });
      return;
    }

    const state = "abcdefg";
    const hashedState = hashStateGuid(state);

    const location = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${clientId}&redirect_uri=http://localhost:4280/.auth/login/google/callback&scope=openid+profile+email&state=${hashedState}`;

    context.res = response({
      context,
      status: 302,
      headers: {
        status: 302,
        Location: location,
      },
      body: "",
    });
    return;
  }

  if (providerName === "github") {
    const clientIdSettingName = customAuth?.identityProviders?.github?.registration?.clientIdSettingName;

    if (!clientIdSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientIdSettingName not found for GitHub provider`,
      });
      return;
    }

    const clientId = process.env[clientIdSettingName];

    if (!clientId) {
      context.res = response({
        context,
        status: 404,
        body: `ClientId not found for GitHub provider`,
      });
      return;
    }

    const state = "abcdefg";
    const hashedState = hashStateGuid(state);

    const location = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=http://localhost:4280/.auth/login/github/callback&scope=read:user&response_type=code&state=${hashedState}`;

    context.res = response({
      context,
      status: 302,
      headers: {
        status: 302,
        Location: location,
      },
      body: "",
    });
    return;
  }

  context.res = response({
    context,
    status: 404,
    body: `Provider ${providerName} not found`,
  });
  return;
};

export default httpTrigger;
