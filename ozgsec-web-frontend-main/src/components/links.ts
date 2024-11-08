import {
  faSquareCheck,
  faGaugeHigh,
  faChartLine,
  faListCheck,
  faInfo,
  faUsers,
  faTag,
} from "@fortawesome/free-solid-svg-icons";
import { User } from "@prisma/client";
import { isAdmin, isFeatureEnabled, isGuestUser } from "../utils/common";
import { FeatureFlag, Guest, ISession } from "../types";

const defaultLinks = [
  {
    icon: faSquareCheck,
    name: "Schnelltest",
    path: "/dashboard/quicktest",
  },
  {
    icon: faGaugeHigh,
    name: "Dashboard",
    path: "/dashboard",
  },
  {
    icon: faChartLine,
    name: "Trendanalyse",
    path: "/dashboard/trends",
  },
  {
    icon: faListCheck,
    name: "Domainübersicht",
    path: "/dashboard/targets",
  },
];
export const getLinks = (
  session: ISession | undefined | null,
  currentUser: User | Guest | null,
) => {
  if (!session || !currentUser || isGuestUser(session.user)) {
    return defaultLinks;
  }
  const links = defaultLinks.concat({
    icon: faInfo,
    name: "Informationen zur OZG-Security-Challenge",
    path: "/dashboard/info",
  });

  return links.concat([
    ...(isFeatureEnabled(FeatureFlag.collections, currentUser as User)
      ? [
          {
            icon: faTag,
            name: "Domain-Gruppen",
            path: "/dashboard/collections",
          },
        ]
      : []),
    ...(isAdmin(session)
      ? [
          {
            icon: faUsers,
            name: "Nutzerverwaltung",
            path: "/dashboard/users",
          },
        ]
      : []),
  ]);
};
