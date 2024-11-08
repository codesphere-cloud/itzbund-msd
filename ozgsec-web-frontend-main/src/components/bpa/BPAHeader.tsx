"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { FunctionComponent, useState } from "react";
import { useSignOut } from "../../hooks/useSignOut";
import { withAuthProvider } from "../../providers/AuthProvider";
import { classNames } from "../../utils/common";
import { useGlobalStore } from "../../zustand/global";
import SideMenu from "../SideMenu";
import MenuButton from "../common/MenuButton";
import { getLinks } from "../links";
import Logo from "./Logo";
import SmallLink from "./SmallLink";
import { featureFlags } from "../../feature-flags";

const BPAHeader: FunctionComponent = () => {
  const activeLink = usePathname();

  const signOut = useSignOut();

  const { user, session, hideLogin } = useGlobalStore();
  const [menuOpen, setMenuOpen] = useState(false);

  const query = useSearchParams();

  return (
    <header className="border-t-10 z-50 bg-white sticky top-0 border-b-6 border-b-hellgrau-40  border-t-bund">
      <div className="container">
        <div className="flex flex-row flex-wrap justify-between items-center">
          <Logo />
          {!hideLogin && (
            <>
              <div className="hidden lg:block">
                <nav className="flex flex-row justify-end">
                  {Boolean(session) ? (
                    <div className="flex flex-row gap-5">
                      <SmallLink href="/dashboard">Dashboard</SmallLink>
                      <span
                        className="uppercase hover:border-b border-b-transparent hover:border-b-blau-100 cursor-pointer font-bold text-xs hover:text-blau-100 text-dunkelgrau-100"
                        onClick={() => {
                          return signOut();
                        }}
                      >
                        Abmelden
                      </span>
                    </div>
                  ) : (
                    featureFlags.dashboardEnabled && (
                      <SmallLink href="/dashboard">Anmelden</SmallLink>
                    )
                  )}
                </nav>
                <nav className="text-gray-600 pt-2 flex flex-row justify-end gap-10">
                  <Link
                    className={classNames(
                      activeLink === "/" ? "text-bund" : "text-textblack",
                      "hover:text-blau-100",
                    )}
                    href={`/?${query}`}
                  >
                    Schnelltest
                  </Link>
                  <Link
                    className={classNames(
                      activeLink === "/info" ? "text-bund" : "text-textblack",
                      "hover:text-blau-100",
                    )}
                    href={`/info?${query}`}
                  >
                    Informationen zur Challenge
                  </Link>
                </nav>
              </div>
              <div className="block ml-auto lg:hidden">
                <MenuButton setMenuOpen={setMenuOpen} menuOpen={menuOpen} />
                <SideMenu
                  isOpen={menuOpen}
                  onClose={() => setMenuOpen((prev) => !prev)}
                >
                  <div>
                    <nav className="flex flex-col">
                      {Boolean(session) ? (
                        <div className="flex flex-col">
                          {getLinks(session, user).map(
                            ({ path, name, icon }) => (
                              <Link
                                key={name}
                                className="hover:no-underline"
                                href={path}
                              >
                                <div
                                  className={classNames(
                                    "py-3 lg:py-5 lg:px-5  flex flex-row items-center lg:hover:bg-hellgrau-20 hover:text-bund lg:hover:text-blau-100 hover:underline lg:hover:no-underline transition-all border-b cursor-pointer",
                                    activeLink === path
                                      ? "text-bund lg:text-blau-100"
                                      : "text-textblack",
                                  )}
                                >
                                  <div className="mr-4">
                                    <FontAwesomeIcon
                                      className="w-5 h-5"
                                      icon={icon}
                                    />
                                  </div>
                                  <span
                                    title={name}
                                    className="whitespace-nowrap hover:no-underline overflow-hidden text-ellipsis"
                                  >
                                    {name}
                                  </span>
                                </div>
                              </Link>
                            ),
                          )}
                          <span
                            className="font-medium cursor-pointer py-3 hover:text-blau-100 hover:underline"
                            onClick={() => {
                              return signOut();
                            }}
                          >
                            Abmelden
                          </span>
                        </div>
                      ) : (
                        <>
                          <Link
                            className={classNames(
                              "py-3",
                              activeLink === "/"
                                ? "text-bund"
                                : "text-textblack",
                              "hover:text-blau-100",
                            )}
                            href={`/?${query}`}
                          >
                            Schnelltest
                          </Link>
                          <Link
                            className={classNames(
                              "py-3",
                              activeLink === "/info"
                                ? "text-bund"
                                : "text-textblack",
                              "hover:text-bund",
                            )}
                            href={`/info?${query}`}
                          >
                            Informationen zur Challenge
                          </Link>

                          {featureFlags.dashboardEnabled && (
                            <Link className="py-3" href="/dashboard">
                              Anmelden
                            </Link>
                          )}
                        </>
                      )}
                    </nav>
                  </div>
                </SideMenu>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
};

export default withAuthProvider(BPAHeader);
