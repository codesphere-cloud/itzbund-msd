import React, { FunctionComponent, useEffect, useRef } from "react";
import { classNames } from "../utils/common";
import { pageTitleNotVisibleEmitter } from "./HeaderTitle";

interface Props {
  className?: string;
  children: React.ReactNode;
  stringRep: string;
}
const PageTitle: FunctionComponent<Props> = ({
  children,
  className,
  stringRep,
}) => {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    // attach an intersection observer to the page title

    let observer: IntersectionObserver;
    if (ref.current) {
      observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            pageTitleNotVisibleEmitter.emit("set-content", "");
          } else {
            pageTitleNotVisibleEmitter.emit("set-content", stringRep);
          }
        });
      });
      observer.observe(ref.current);
    }
    return () => {
      if (observer) observer.disconnect();
      pageTitleNotVisibleEmitter.emit("set-content", "");
    };
  }, [stringRep]);

  return (
    <h1
      ref={ref}
      className={classNames(className ?? "text-4xl mb-5 text-white font-bold")}
      id="page-title"
    >
      {children}
    </h1>
  );
};

export default PageTitle;
