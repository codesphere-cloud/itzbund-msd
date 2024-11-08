import { PropsWithChildren } from "react";
import Header from "../../components/Header";
import SideNavigation from "../../components/SideNavigation";
import { authOptions } from "../../nextAuthOptions";
import { getSessionAndUser } from "../../utils/server";
import { GlobalStoreProvider } from "../../zustand/GlobalStoreProvider";

// disable static evaluation
export const dynamic = "force-dynamic";

const title = "Dashboard - OZG-Security-Challenge 2023";
const description =
  "OZG Security Schnelltest einer Webseite in Bezug auf IT-Sicherheitsmaßnahmen und Best-Practices";

export const metadata = {
  title,
  description,
  openGraph: {
    title,
    description,
    type: "website",
  },
};

type Props = PropsWithChildren;
const DashboardLayout = async ({ children }: Props) => {
  const { session, user } = await getSessionAndUser(authOptions);

  if (!session || !user) {
    // should be catched by the middleware already
    return null;
  }

  return (
    <GlobalStoreProvider session={session} user={user}>
      <div id="dashboard-layout">
        <div className="flex-row min-h-screen text-base flex w-full flex-1">
          <div className="hidden min-h-screen lg:block">
            <SideNavigation user={user} session={session} />
          </div>
          <div className="flex-1 flex flex-col">
            <Header session={session} />
            <main className="py-10 text-base flex-col bg-white flex flex-1">
              <div className="max-w-screen-2xl md:px-8 px-4 w-full flex-1 mx-auto">
                {children}
              </div>
            </main>
          </div>
        </div>
      </div>
    </GlobalStoreProvider>
  );
};

export default DashboardLayout;
