import React, { FunctionComponent } from "react";

interface Props {
  setMenuOpen: React.Dispatch<React.SetStateAction<boolean>>;
  menuOpen: boolean;
}
const MenuButton: FunctionComponent<Props> = ({ setMenuOpen, menuOpen }) => {
  return (
    <button
      role="button"
      aria-label="Menü öffnen"
      className="w-12 p-3 text-blau-100 flex flex-row justify-center items-center fill-current"
      onClick={() => {
        setMenuOpen((prev) => !prev);
      }}
    >
      {menuOpen ? (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14">
          <path
            d="m8.4 7 5.4-5.4a.2.2 0 0 0 0-.3l-1-1a.2.2 0 0 0-.4 0L7 5.5 1.6.2a.2.2 0 0 0-.3 0l-1 1a.2.2 0 0 0 0 .4L5.5 7 .2 12.4a.2.2 0 0 0 0 .3l1 1a.2.2 0 0 0 .4 0L7 8.5l5.4 5.4a.2.2 0 0 0 .3 0l1-1a.2.2 0 0 0 0-.4Z"
            data-name="close"
          />
        </svg>
      ) : (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 14">
          <g data-name="menu">
            <rect x="1" y="1" width="18" height="2" rx=".3" ry=".3" />
            <rect x="1" y="6" width="18" height="2" rx=".3" ry=".3" />
            <rect x="1" y="11" width="18" height="2" rx=".3" ry=".3" />
          </g>
        </svg>
      )}
    </button>
  );
};

export default MenuButton;
