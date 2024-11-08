import { User } from "@prisma/client";
import BPAHeader from "../../components/bpa/BPAHeader";
import { authOptions } from "../../nextAuthOptions";
import { ISession } from "../../types";
import { getSessionAndUser } from "../../utils/server";
import { GlobalStoreProvider } from "../../zustand/GlobalStoreProvider";

const Layout = async ({ children }: any) => {
  let session: ISession | undefined;
  let user: User | undefined;

  try {
    const resp = await getSessionAndUser(authOptions);
    session = resp.session;
    user = resp.user;
  } catch {}

  return (
    <GlobalStoreProvider session={session} user={user}>
      <div id="index-layout">
        <BPAHeader />
        <main>{children}</main>
      </div>
    </GlobalStoreProvider>
  );
};

export default Layout;
