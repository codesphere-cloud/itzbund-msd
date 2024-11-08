"use client";
import React, { FunctionComponent, useEffect } from "react";
import Article from "../../../components/common/Article";
import { useGlobalStore } from "../../../zustand/global";

interface Props {
  displayNotAvailable: boolean;
}
const Content: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  const store = useGlobalStore();
  useEffect(() => {
    store.setHideLogin(displayNotAvailable);
  }, [displayNotAvailable]);
  return (
    <Article title="Impressum" teaser="">
      <p>
        <br />
        <br />
        <strong>Das Internetangebot wird herausgegeben vom</strong>
        <br />
      </p>
    </Article>
  );
};

export default Content;
