import React from 'react';
import Logo from './Logo';

const Header = () => {
    return (
        <header className="border-t-10 z-9999 sticky bg-white top-0 border-b-6 border-b-hellgrau-40  border-t-bund">

<div className="tw-container">
  <div className="flex flex-row flex-wrap justify-between items-center">
    <Logo />
  </div>
</div>
</header>
    );
};

export default Header;

