"use client";
import { signIn, useSession } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";
import { withAuthProvider } from "../../../providers/AuthProvider";
import { ISession } from "../../../types";

const SignIn = () => {
  const session = useSession();
  let data: typeof session.data | undefined = undefined;
  let status: typeof session.status | undefined = undefined;
  if (session) {
    data = session.data;
    status = session.status;
  }
  const query = useSearchParams();
  const router = useRouter();
  const ref = useRef<"idle" | "redirecting">("idle");

  useEffect(() => {
    // check the query
    const secret = query?.get("secret");
    if (secret) {
      void signIn("credentials", {
        shareLinkSecret: secret,
        callbackUrl: "/dashboard",
      });
      return;
    }

    if (
      status === "unauthenticated" ||
      (data as unknown as ISession)?.error !== undefined
    ) {
      void signIn("keycloak");
    } else if (status === "authenticated") {
      if (ref.current === "idle") {
        ref.current = "redirecting";
        void router.push("/dashboard");
      }
    }
  }, [query, status, router, data]);

  return null;
};

export default withAuthProvider(SignIn);
