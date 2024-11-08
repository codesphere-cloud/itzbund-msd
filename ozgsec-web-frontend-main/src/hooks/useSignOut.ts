import { signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import { isGuestUser } from "../utils/common";
import { useSession } from "./useSession";

export function useSignOut() {
  const router = useRouter();
  const session = useSession();
  const handleSignOut = async () => {
    if (session.data && isGuestUser(session.data.user)) {
      await signOut({
        redirect: false,
      });
      router.push("/");
    } else {
      const res: { path: string } = await (
        await fetch("/api/auth/kc-signout")
      ).json();
      await signOut({
        redirect: false,
      });
      router.push(res.path);
    }
  };

  return handleSignOut;
}
