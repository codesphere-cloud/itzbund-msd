"use client";

import React from "react";

const ScrollUpButton = () => {
  return (
    <div
      role="button"
      aria-label="Zum Seitenanfang scrollen"
      onClick={() => {
        // scroll to top
        window.scrollTo({ top: 0, behavior: "smooth" });
      }}
      className="border-2 border-white hover:bg-white p-3 flex transition-all flex-row items-center justify-center text-white hover:text-bund rounded-full cursor-pointer"
    >
      <svg
        className="w-5 h-5 -rotate-90 relative fill-current"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 8 12"
      >
        <path
          d="M7.1 5.8 1.5.2a.2.2 0 0 0-.3 0l-1 1a.2.2 0 0 0 0 .4L4.4 6 0 10.4a.2.2 0 0 0 0 .3l1 1a.2.2 0 0 0 .4 0l5.6-5.5a.3.3 0 0 0 0-.4Z"
          data-name="slide-right"
        />
      </svg>
    </div>
  );
};

export default ScrollUpButton;
