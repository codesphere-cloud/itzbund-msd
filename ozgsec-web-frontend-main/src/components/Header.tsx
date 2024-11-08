import {
  faEnvelope,
  faHeadset,
  faKey,
  faPhone,
  faUserAstronaut,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { FunctionComponent } from "react";
import { ISession } from "../types";
import { classNames, isGuestUser } from "../utils/common";
import HeaderTitle from "./HeaderTitle";
import MobileMenu from "./MobileMenu";
import DropdownMenuItem from "./common/DropdownMenuItem";
import LogoutMenuItem from "./common/LogoutMenuItem";
import Menu from "./common/Menu";
import Tooltip from "./common/Tooltip";
import NotificationCenter from "./NotificationCenter";

const Header: FunctionComponent<{ session: ISession | null }> = ({
  session,
}) => {
  return (
    <header
      className={classNames(
        "sticky top-0 border-t-bund border-t-6 transition-all z-100 duration-500 text-textblack border-b-6 border-b-hellgrau-40",
        "bg-white",
      )}
    >
      {session !== null && (
        <div className="h-20 flex flex-row items-center">
          <div className="flex flex-1 md:px-8 px-4 max-w-screen-2xl mx-auto flex-row justify-between items-center">
            <HeaderTitle />
            <div className="block lg:hidden">
              <div className="block ml-auto lg:hidden">
                <MobileMenu />
              </div>
            </div>
            <div className="ml-2 text-sm absolute z-200 hidden lg:block right-2 text-white">
              <div className="flex flex-row gap-5 items-center">
                <Tooltip
                  tooltip={
                    <div className="grid gap-2 text-sm">
                      <div className="flex flex-col font-semibold">
                        <span>Fragen zur Challenge oder zum Dashboard?</span>
                        <span className="">Hier wird Ihnen geholfen!</span>
                      </div>
                      <div className="pb-2 flex flex-col gap-4">
                        <div
                          key="sprechstunde"
                          className="flex items-start gap-x-3"
                        >
                          <FontAwesomeIcon
                            className="h-7 w-7 pt-2 flex-none"
                            icon={faPhone}
                          />
                          <span>
                            <a
                              href="tel:+4920878012422"
                              className="text-blau-100"
                            >
                              0208 78012422
                            </a>
                            <br />
                            Sprechstunde
                            <br /> (Mo. 10:00 - 12:00 Uhr)
                          </span>
                        </div>
                        <div
                          key="one-pager"
                          className="flex items-start gap-x-3"
                        >
                          <FontAwesomeIcon
                            className="h-7 w-7 pt-2 flex-none"
                            icon={faEnvelope}
                          />
                          <span>
                            <a
                              href="mailto:ozgsec@bmi.bund.de"
                              className="text-blau-100"
                            >
                              ozgsec@bmi.bund.de
                            </a>
                          </span>
                        </div>
                      </div>
                    </div>
                  }
                >
                  <div className="flex cursor-pointer text-sm text-textblack flex-row gap-2">
                    <FontAwesomeIcon size="xl" icon={faHeadset} />
                  </div>
                </Tooltip>

                <Menu
                  Button={
                    <div
                      aria-label="Benutzermenü öffnen"
                      className="bg-hellgrau-60 text-textblack overflow-hidden cursor-pointer rounded-full h-9 w-9 flex items-center justify-center text-xs mr-1"
                    >
                      <FontAwesomeIcon
                        size={"2xl"}
                        className="relative -bottom-1.5"
                        icon={faUserAstronaut}
                      />
                    </div>
                  }
                  Menu={
                    <>
                      <LogoutMenuItem />
                      {!isGuestUser(session.user) && (
                        <a
                          className="hover:no-underline font-normal"
                          href={`/auth/change-password`}
                        >
                          <DropdownMenuItem
                            Icon={<FontAwesomeIcon icon={faKey} />}
                          >
                            Passwort ändern
                          </DropdownMenuItem>
                        </a>
                      )}
                      <div className="p-2 relative top-1 border-t border-t-hellgrau-40 bg-white text-textblack">
                        Eingeloggt als:{" "}
                        {isGuestUser(session.user) ? "Gast" : session.user.name}
                      </div>
                    </>
                  }
                />
              </div>
            </div>
          </div>
        </div>
      )}
      <div>
        <NotificationCenter />
      </div>
    </header>
  );
};

export default Header;
