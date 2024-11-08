"use client";

import { faArrowRightFromBracket } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { useSignOut } from "../../hooks/useSignOut";
import DropdownMenuItem from "./DropdownMenuItem";
import { withAuthProvider } from "../../providers/AuthProvider";

const LogoutMenuItem = () => {
  const signOut = useSignOut();
  return (
    <DropdownMenuItem
      Icon={<FontAwesomeIcon icon={faArrowRightFromBracket} />}
      onClick={() => signOut()}
    >
      Ausloggen
    </DropdownMenuItem>
  );
};

export default withAuthProvider(LogoutMenuItem);
