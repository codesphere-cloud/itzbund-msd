import React from "react";

export function withNotAvailable<P extends { displayNotAvailable: boolean }>(
  Component: React.ComponentType<P>,
) {
  return async function WithAuthProvider(
    props: Omit<P, "displayNotAvailable"> & {
      searchParams: Record<string, string>;
    },
  ) {
    let displayNotAvailable = false;

    /*
    This code was part of the initial implementation. It was used to hide the scanner, if no valid code via the searchParams was provided.

    if (featureFlags.dashboardEnabled) {
      const code = props.searchParams["s"];

      const session = await getServerSession(authOptions);

      displayNotAvailable = false; //  session === null &&(!Boolean(code) || code === null || !staticSecrets[code]);
    }
    */

    return (
      <Component
        displayNotAvailable={displayNotAvailable}
        {...(props as any)}
      />
    );
  };
}
