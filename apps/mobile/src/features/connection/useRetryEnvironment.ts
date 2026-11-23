import { RegistryContext, useAtomValue } from "@effect/atom-react";
import type { EnvironmentId } from "@t3tools/contracts";
import { AsyncResult } from "effect/reactivity";
import { useContext } from "react";

import { environmentCatalog } from "../../connection/catalog";
import { connectBrowserSession } from "../../connection/onboarding";
import { useAtomCommand } from "../../state/use-atom-command";

export function useRetryEnvironment() {
  const registry = useContext(RegistryContext);
  const catalog = useAtomValue(environmentCatalog.catalogValueAtom);
  const retryNow = useAtomCommand(environmentCatalog.retryNow, "environment retry");
  const setEnabled = useAtomCommand(environmentCatalog.setEnabled, "environment toggle");
  const signIn = useAtomCommand(connectBrowserSession, "environment sign-in");

  return async (environmentId: EnvironmentId) => {
    const entry = catalog.entries.get(environmentId);
    // A retry does nothing while the environment is switched off.
    if (entry?.enabled === false) return setEnabled({ environmentId, enabled: true });
    const profile = entry?.profile._tag === "Some" ? entry.profile.value : null;
    if (
      profile?._tag === "BearerConnectionProfile" &&
      profile.authorization === "browser-session"
    ) {
      const state = AsyncResult.getOrElse(
        registry.get(environmentCatalog.stateAtom(environmentId)),
        () => null,
      );
      if (state?.phase === "blocked" && state.lastFailure?.reason === "authentication") {
        const signedIn = await signIn({
          host: profile.httpBaseUrl,
          expectedEnvironmentId: environmentId,
        });
        if (signedIn._tag === "Failure") return signedIn;
      }
    }
    return retryNow(environmentId);
  };
}
