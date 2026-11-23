import { connectionRoutes } from "@t3tools/client-runtime/connection";
import { msg } from "gt-react";
import { useEffect } from "react";

import { environmentCatalog } from "../../connection/catalog";
import { m } from "../../i18n/messages";
import { appAtomRegistry } from "../../rpc/atomRegistry";
import { useAtomCommand } from "../../state/use-atom-command";
import { stackedThreadToast, toastManager } from "../ui/toast";

function routeOrigin(httpBaseUrl: string): string | null {
  try {
    return new URL(httpBaseUrl).origin;
  } catch {
    return null;
  }
}

export function EnvironmentSignInCoordinator() {
  const retryEnvironment = useAtomCommand(environmentCatalog.retryNow, { reportFailure: false });

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- desktop IPC listener and toasts held until unmount
  useEffect(() => {
    const bridge = window.desktopBridge;
    const subscribe = bridge?.onEnvironmentSignInRequired;
    const signIn = bridge?.signInToEnvironment;
    if (subscribe === undefined || signIn === undefined) return;
    const toasts = new Map<string, ReturnType<typeof toastManager.add>>();
    const retryOrigin = (origin: string) => {
      const { entries } = appAtomRegistry.get(environmentCatalog.catalogValueAtom);
      for (const [environmentId, entry] of entries) {
        const matches = connectionRoutes(entry).some(
          (route) =>
            route.profile._tag === "Some" &&
            route.profile.value._tag === "BearerConnectionProfile" &&
            routeOrigin(route.profile.value.httpBaseUrl) === origin,
        );
        if (matches) void retryEnvironment(environmentId);
      }
    };
    const unsubscribe = subscribe((origin) => {
      if (toasts.has(origin)) return;
      const host = new URL(origin).host;
      const toastId = toastManager.add(
        stackedThreadToast({
          type: "warning",
          title: m(msg("Sign in to {host}", { host })),
          description: m(msg("The sign-in session for this environment ended.")),
          timeout: 0,
          actionProps: {
            children: m(msg("Sign in")),
            onClick: () => {
              void signIn(origin).then((result) => {
                if (result !== "ready") return;
                toastManager.close(toastId);
                toasts.delete(origin);
                retryOrigin(origin);
              });
            },
          },
          data: { hideCopyButton: true },
        }),
      );
      toasts.set(origin, toastId);
    });
    return () => {
      unsubscribe();
      for (const toastId of toasts.values()) toastManager.close(toastId);
    };
  }, [retryEnvironment]);

  return null;
}
