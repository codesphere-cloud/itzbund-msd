"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect } from "react";
import { useSignOut } from "../hooks/useSignOut";
import { classNames } from "../utils/common";
import { useGlobalStore } from "../zustand/global";
import SideMenu from "./SideMenu";
import MenuButton from "./common/MenuButton";
import { getLinks } from "./links";
import { withAuthProvider } from "../providers/AuthProvider";

const MobileMenu = () => {
  const [menuOpen, setMenuOpen] = React.useState(false);
  const pathname = usePathname();
  const { session, user } = useGlobalStore();

  const signOut = useSignOut();
  useEffect(() => {
    // always close the menu when the route changes
    setMenuOpen(false);
  }, [pathname]);
  return (
    <>
      <MenuButton setMenuOpen={setMenuOpen} menuOpen={menuOpen} />
      <SideMenu isOpen={menuOpen} onClose={() => setMenuOpen((prev) => !prev)}>
        <div>
          <nav className="flex text-base flex-col">
            {getLinks(session, user).map(({ path, name, icon }) => (
              <Link key={name} className="hover:no-underline" href={path}>
                <div
                  className={classNames(
                    "py-3 lg:py-5 lg:px-5  flex flex-row items-center lg:hover:bg-hellgrau-20 hover:text-bund lg:hover:text-blau-100 hover:underline lg:hover:no-underline transition-all border-b cursor-pointer",
                    pathname === path
                      ? "text-bund lg:text-blau-100"
                      : "text-textblack",
                  )}
                >
                  <div className="mr-4">
                    <FontAwesomeIcon className="w-5 h-5" icon={icon} />
                  </div>
                  <span
                    title={name}
                    className="whitespace-nowrap hover:no-underline overflow-hidden text-ellipsis"
                  >
                    {name}
                  </span>
                </div>
              </Link>
            ))}
          </nav>
          <a role="button" onClick={signOut} className="py-3 ml-9">
            Abmelden
          </a>
          <Image
            className="absolute bottom-5"
            src={"/assets/BMI_de_v3__BSI_de_v1__Web_farbig.svg"}
            width={280}
            height={120}
            alt="Logo BMI und BSI"
          />
        </div>
      </SideMenu>
    </>
  );
};

export default withAuthProvider(MobileMenu);
