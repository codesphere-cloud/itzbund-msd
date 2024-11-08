"use client";

import { FunctionComponent, PropsWithChildren, useEffect, useRef } from "react";
import { GlobalStore, GlobalStoreContext, createGlobalStore } from "./global";

import { User } from "@prisma/client";
import { ISession } from "../types";

interface Props {
  session?: ISession;
  user?: User;
}
export const GlobalStoreProvider: FunctionComponent<
  PropsWithChildren<Props>
> = ({ children, ...props }) => {
  const storeRef = useRef<GlobalStore>();
  if (!storeRef.current) {
    storeRef.current = createGlobalStore({
      ...props,
      sideMenuCollapsed: false,
      hideLogin: true,
      user: props.user ?? null,
      session: props.session ?? null,
    });
  }

  useEffect(() => {
    // late initialization for the store - this is needed, since some web browser client apis are not available during SSR. Like localstorage
    storeRef.current?.setState({
      sideMenuCollapsed: localStorage.getItem("collapsed") === "true",
    });
  }, []);

  return (
    <GlobalStoreContext.Provider value={storeRef.current}>
      {children}
    </GlobalStoreContext.Provider>
  );
};
