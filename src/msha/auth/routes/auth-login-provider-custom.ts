import { response } from "../../../core";
import crypto from "crypto";
const hashStateGuid = function (guid: string) {
  const hash = crypto.createHmac("sha256", process.env.SALT || "");
  hash.update(guid);
  return hash.digest("hex");
};

const httpTrigger = async function (context: Context) {
  await Promise.resolve();
  const clientId = process.env.GITHUB_CLIENT_ID;
  const state = "abcdefg";
  const hashedState = hashStateGuid(state);

  context.res = response({
    context,
    status: 302,
    headers: {
      status: 302,
      Location: `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=http://localhost:4280/.auth/login/github/callback&scope=read:user&response_type=code&state=${hashedState}`,
    },
    body: "",
  });
};

export default httpTrigger;
