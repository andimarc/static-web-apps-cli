import { parseUrl, response } from "../../../core";
import crypto from "crypto";
import * as http from "http";
import * as https from "https";
import * as querystring from "querystring";
import { SWA_CLI_API_URI, SWA_CLI_APP_PROTOCOL } from "../../../core/constants";

const hashStateGuid = function (guid: string) {
  const hash = crypto.createHmac("sha256", process.env.SALT || "");
  hash.update(guid);
  return hash.digest("hex");
};

const getGithubAuthToken = function (codeValue: string, clientId: string, clientSecret: string) {
  const hashedState = hashStateGuid("abcdefg");
  console.log(hashedState);

  const data = querystring.stringify({
    code: codeValue,
    client_id: clientId,
    client_secret: clientSecret,
  });

  const options = {
    host: "github.com",
    path: "/login/oauth/access_token",
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(data),
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        resolve(responseBody);
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.write(data);
    req.end();
  });
};

const getGitHubUser = function (accessToken: string) {
  const hashedState = hashStateGuid("abcdefg");
  console.log(hashedState);

  const options = {
    host: "api.github.com",
    path: "/user",
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "Azure Static Web Apps Emulator",
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        resolve(JSON.parse(responseBody));
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.end();
  });
};

const getGoogleAuthToken = function (codeValue: string, clientId: string, clientSecret: string) {
  const hashedState = hashStateGuid("abcdefg");
  console.log(hashedState);

  const data = querystring.stringify({
    code: codeValue,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    redirect_uri: "http://localhost:4280/.auth/login/google/callback",
  });

  const options = {
    host: "oauth2.googleapis.com",
    path: "/token",
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(data),
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        resolve(responseBody);
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.write(data);
    req.end();
  });
};

const getGoogleUser = function (accessToken: string) {
  const hashedState = hashStateGuid("abcdefg");
  console.log(hashedState);

  const options = {
    host: "googleapis.com",
    path: "/oauth2/v1/userinfo",
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "Azure Static Web Apps Emulator",
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        resolve(JSON.parse(responseBody));
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.end();
  });
};

const getRoles = function (clientPrincipal: RolesSourceFunctionRequestBody) {
  let cliApiUri = SWA_CLI_API_URI();
  const { protocol, hostname, port } = parseUrl(cliApiUri);
  const target = hostname === "localhost" ? `${protocol}//127.0.0.1:${port}` : cliApiUri;
  const targetUrl = new URL(target!);

  console.log(target);

  const data = JSON.stringify(clientPrincipal);

  const options = {
    host: targetUrl.hostname,
    port: targetUrl.port,
    path: "/api/GetRoles",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
    },
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      res.setEncoding("utf8");
      let responseBody = "";

      res.on("data", (chunk) => {
        responseBody += chunk;
      });

      res.on("end", () => {
        resolve(JSON.parse(responseBody));
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.write(data);
    req.end();
  });
};

const httpTrigger = async function (context: Context, request: http.IncomingMessage, customAuth?: SWAConfigFileAuth) {
  console.log(request.url);

  const url = new URL(request.url!, `${SWA_CLI_APP_PROTOCOL}://${request?.headers?.host}`);

  const stateValue = url.searchParams.get("state");
  console.log(`state: ${stateValue}`);

  const codeValue = url.searchParams.get("code");
  console.log(`code: ${codeValue}`);

  if (context.bindingData?.provider === "github") {
    const { clientIdSettingName, clientSecretSettingName } = customAuth?.identityProviders?.github?.registration || {};

    if (!clientIdSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientIdSettingName not found for GitHub provider`,
      });
      return;
    }

    if (!clientSecretSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientSecretSettingName not found for GitHub provider`,
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

    const clientSecret = process.env[clientSecretSettingName];

    if (!clientSecret) {
      context.res = response({
        context,
        status: 404,
        body: `ClientSecret not found for Google provider`,
      });
      return;
    }

    const authTokenResponse = (await getGithubAuthToken(codeValue!, clientId, clientSecret)) as string;
    console.log(authTokenResponse);

    const authTokenParsed = querystring.parse(authTokenResponse);

    const authToken = authTokenParsed["access_token"] as string;

    const user = (await getGitHubUser(authToken)) as { [key: string]: string };

    console.log(authToken);

    const userId = user["id"];
    const userDetails = user["login"];

    const claims: { typ: string; val: string }[] = [
      {
        typ: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        val: userId,
      },
    ];

    Object.keys(user).forEach((key) => {
      claims.push({
        typ: `urn:github:${key}`,
        val: user[key],
      });
    });

    const clientPrincipal = {
      identityProvider: context.bindingData.provider,
      userId,
      userDetails,
      claims,
      userRoles: ["authenticated", "anonymous"],
    };

    const rolesResult = (await getRoles(clientPrincipal)) as { roles: string[] };

    clientPrincipal.userRoles.push(...rolesResult.roles);

    context.res = response({
      context,
      cookies: [
        {
          name: "StaticWebAppsAuthCookie",
          value: btoa(JSON.stringify(clientPrincipal)),
          domain: "localhost",
          path: "/",
          expires: new Date(Date.now() + 1000 * 60 * 60),
        },
      ],
      status: 302,
      headers: {
        status: 302,
        Location: `http://localhost:4280`,
      },
      body: "",
    });
  } else if (context.bindingData?.provider === "google") {
    const { clientIdSettingName, clientSecretSettingName } = customAuth?.identityProviders?.google?.registration || {};

    if (!clientIdSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientIdSettingName not found for Google provider`,
      });
      return;
    }

    if (!clientSecretSettingName) {
      context.res = response({
        context,
        status: 404,
        body: `ClientSecretSettingName not found for Google provider`,
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

    const clientSecret = process.env[clientSecretSettingName];

    if (!clientSecret) {
      context.res = response({
        context,
        status: 404,
        body: `ClientSecret not found for Google provider`,
      });
      return;
    }

    const authTokenResponse = (await getGoogleAuthToken(codeValue!, clientId, clientSecret)) as string;
    console.log(authTokenResponse);

    const authTokenParsed = querystring.parse(authTokenResponse);

    const authToken = authTokenParsed["access_token"] as string;

    const user = (await getGoogleUser(authToken)) as { [key: string]: string };

    console.log(authToken);

    const userId = user["id"];
    const userDetails = user["login"];

    const claims: { typ: string; val: string }[] = [
      {
        typ: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        val: userId,
      },
    ];

    Object.keys(user).forEach((key) => {
      claims.push({
        typ: `urn:google:${key}`,
        val: user[key],
      });
    });

    const clientPrincipal = {
      identityProvider: context.bindingData.provider,
      userId,
      userDetails,
      claims,
      userRoles: ["authenticated", "anonymous"],
    };

    const rolesResult = (await getRoles(clientPrincipal)) as { roles: string[] };

    clientPrincipal.userRoles.push(...rolesResult.roles);

    context.res = response({
      context,
      cookies: [
        {
          name: "StaticWebAppsAuthCookie",
          value: btoa(JSON.stringify(clientPrincipal)),
          domain: "localhost",
          path: "/",
          expires: new Date(Date.now() + 1000 * 60 * 60),
        },
      ],
      status: 302,
      headers: {
        status: 302,
        Location: `http://localhost:4280`,
      },
      body: "",
    });
  }
};

export default httpTrigger;
