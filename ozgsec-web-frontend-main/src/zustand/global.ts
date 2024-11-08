import { User } from "@prisma/client";
import { createContext, useContext } from "react";
import { StoreApi, createStore, useStore } from "zustand";
import { Guest, ISession } from "../types";
interface GlobalState {
  session: ISession | null;
  setSession: (val: ISession | null) => void;

  user: User | Guest | null;
  setUser: (val: User | Guest) => void;

  sideMenuCollapsed: boolean;
  setSideMenuCollapsed: (val: boolean) => void;
  hideLogin: boolean;
  setHideLogin: (val: boolean) => void;
}

export type GlobalStore = StoreApi<GlobalState>;

export interface GlobalStoreProps {
  sideMenuCollapsed: boolean;
  hideLogin: boolean;
  session: ISession | null;
  user: User | Guest | null;
}

export const createGlobalStore = (initProps: GlobalStoreProps): GlobalStore => {
  return createStore<GlobalState>()((set) => ({
    setSideMenuCollapsed: (val: boolean) => {
      // save the state inside localStorage
      localStorage.setItem("collapsed", val ? "true" : "false");
      return set(() => ({ sideMenuCollapsed: val }));
    },
    setHideLogin: (val: boolean) => set(() => ({ hideLogin: val })),
    setSession: (val: ISession | null) => set(() => ({ session: val })),
    setUser: (val: User | Guest) => set(() => ({ user: val })),
    ...initProps,
  }));
};

export const GlobalStoreContext = createContext<GlobalStore | null>(null);

export function useGlobalStore(): GlobalState;
export function useGlobalStore<T>(
  selector: (state: GlobalState) => T,
  equalityFn?: (left: T, right: T) => boolean,
): T;
export function useGlobalStore<T>(
  selector?: (state: GlobalState) => T,
  equalityFn?: (left: T, right: T) => boolean,
): T {
  const store = useContext(GlobalStoreContext);
  if (!store)
    throw new Error("Missing GlobalStoreContext.Provider in the tree");
  return useStore(store, selector ?? ((state) => state as T), equalityFn);
}
