"use client";

import EventEmitter from "events";
import React, { useEffect, useState } from "react";
import { classNames } from "../utils/common";

export const pageTitleNotVisibleEmitter = new EventEmitter();

const HeaderTitle = () => {
  const [title, setTitle] = useState("");
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    pageTitleNotVisibleEmitter.on("set-content", (args) => {
      setTitle(args);
    });
    const listener = () => {
      if (window.scrollY > 0 && !scrolled) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };
    listener();
    // add scroll listener
    window.addEventListener("scroll", listener);

    return () => {
      pageTitleNotVisibleEmitter.removeAllListeners("set-content");
      // remove scroll listener
      window.removeEventListener("scroll", listener);
    };
  }, []);
  return (
    <h2
      className={classNames(
        "text-textblack text-xl font-bold transition duration-500",
        title === "" ? "opacity-0" : "opacity-100",
      )}
    >
      {title}
    </h2>
  );
};

export default HeaderTitle;
