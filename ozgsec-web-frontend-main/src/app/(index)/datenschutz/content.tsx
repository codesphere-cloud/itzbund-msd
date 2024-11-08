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
    <Article
      title="Datenschutz"
      teaser="Die nachfolgenden Datenschutzhinweise geben einen Überblick über die Erhebung und Verarbeitung Ihrer Daten."
    >
      <div>
        {/* The following section merely serves as an orientation 
        for the specification of all relevant cookies used. However, 
        no claim is made to completeness. Depending on the operating 
        environment or your own adjustments, deviations may occur. 
        Therefore, please check which cookies are used when creating 
        your data protection information.  */}
        <br />
        <b>Cookie-Einsatz</b>
        <br />
        Beim Aufruf der Plattform mit der Eingabe-Maske erheben wir während
        einer laufenden Verbindung über Ihren Internetbrowser und mit Hilfe von
        technisch notwendigen sog. Session-Cookies keine personenbezogenen
        Daten. Das Session Cookie basiert nicht auf der IP-Adresse des Nutzers
        oder einer sonstigen zu dem tatsächlichen Nutzer zurückverfolgbaren
        Information. Seine Gültigkeit endet mit Ablauf der aktuellen Sitzung und
        die Session-ID ist nur auf dem jeweiligen Server gültig und wird nicht
        über verschiedene Server-Instanzen synchronisiert.
        <br />
        <br />
        Folgende technisch notwendige Cookies werden gesetzt:
        <br />
        <br />
        NextJS setzt:
        <ul className="list-disc list-inside mt-2">
          <li>Secure-next-auth.session-token.x</li>
          <li>Secure-next-auth.callback-url</li>
          <li>Host-next-auth.csrf-token</li>
          <li>Secure-next-auth.pkce.code_verifier</li>
          <li>Secure-next-auth.state</li>
        </ul>
        <br />
        Keycloak setzt:
        <ul className="list-disc list-inside mt-2">
          <li>KEYCLOAK_SESSION</li>
          <li>KEYCLOAK_SESSION_LEGACY</li>
          <li>KEYCLOAK_LOCALE</li>
          <li>AUTH_SESSION_ID</li>
          <li>AUTH_SESSION_ID_LEGACY</li>
          <li>KEYCLOAK_IDENTITY</li>
          <li>KEYCLOAK_IDENTITY_LEGACY</li>
          <li>KC_RESTART</li>
          <li>KEYCLOAK_REMEMBER_ME</li>
        </ul>
        <br />
        <br />
      </div>
    </Article>
  );
};

export default Content;
