import * as Schema from "effect/Schema";
import * as Effect from "effect/Effect";

import * as DesktopEnvironmentSignIn from "../../environmentSignIn/DesktopEnvironmentSignIn.ts";
import * as IpcChannels from "../channels.ts";
import * as DesktopIpc from "../DesktopIpc.ts";

export const signInToEnvironment = DesktopIpc.makeIpcMethod({
  channel: IpcChannels.SIGN_IN_TO_ENVIRONMENT_CHANNEL,
  payload: Schema.String,
  result: DesktopEnvironmentSignIn.DesktopEnvironmentSignInResult,
  handler: Effect.fn("desktop.ipc.environmentSignIn.signIn")(function* (httpBaseUrl) {
    const signIn = yield* DesktopEnvironmentSignIn.DesktopEnvironmentSignIn;
    return yield* signIn.signIn(httpBaseUrl);
  }),
});
