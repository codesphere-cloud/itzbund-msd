"use client";
import Image from "next/image";
import Link from "next/link";
import Article from "./common/Article";
import React, { FunctionComponent, useEffect } from "react";
import { useGlobalStore } from "../zustand/global";

interface Props {
  displayNotAvailable: boolean;
}

const InfoContent: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  const store = useGlobalStore();
  useEffect(() => {
    store.setHideLogin(displayNotAvailable);
  }, [displayNotAvailable]);
  return (
    <Article
      teaser="Das Bundesministerium des Innern und für Heimat (BMI) möchte zur Stärkung der IT-Sicherheit bei der OZG-Umsetzung in Form einer Challenge beitragen. Bis zum 31. Oktober 2023 haben OZG-Dienstverantwortliche im Rahmen der „OZG-Security-Challenge 2023“ die Möglichkeit, die IT-Sicherheit der OZG-Onlinedienste mithilfe eines zugangsgeschützten Schnelltests sowie unterstützt durch Workshops und Sprechstunden weiter zu steigern."
      title="Die OZG-Security-Challenge 2023: Gemeinsam zu mehr IT-Sicherheit"
    >
      <div
        style={{ height: 392 }}
        className="flex flex-row mt-10 justify-center overflow-hidden relative"
      >
        <div className="absolute -top-10 -bottom-10 -left-10 -right-10">
          <Image
            alt="OZG Security Schnelltest"
            fill
            className="object-cover blur-2xl"
            src={"/assets/OZG_Security-Challenge_Headerbild.png"}
          />
        </div>
        <Image
          alt="OZG Security Schnelltest"
          width={700}
          height={0}
          quality={100}
          className={"z-10 object-contain"}
          placeholder="empty"
          src={"/assets/OZG_Security-Challenge_Headerbild.png"}
        />
      </div>

      <div className="mt-10">
        <p>
          Mit der zunehmenden Digitalisierung der öffentlichen Verwaltung steigt
          die Bedeutung der zugrundeliegenden Informationssicherheit.
          Bürgerinnen, Bürger und Unternehmen erwarten, dass der Staat
          vertrauensvoll mit ihren persönlichen Daten umgeht und diese durch ein
          hohes Maß an IT-Sicherheit schützt. Das Bundesministerium des Innern
          und für Heimat (BMI) möchte daher die Steigerung der IT-Sicherheit bei
          der OZG-Umsetzung weiter vorantreiben und hat in Zusammenarbeit mit
          dem Bundesamt für Sicherheit in der Informationstechnik (BSI) die
          „OZG-Security-Challenge 2023“ ins Leben gerufen.
        </p>

        <h2>Die Challenge im Überblick</h2>
        <div className="desc sm:float-right rounded-sm sm:mx-2 mb-2 text-left bg-hellgrau-20 p-5">
          <b>Sprechstunde:</b>
          <br />
          <a href="tel:+4920878012422" className="font-normal">
            0208 78012422
          </a>{" "}
          (Mo. 10-12 Uhr)
          <br />
          <a href="mailto:ozgsec@bmi.bund.de">ozgsec@bmi.bund.de</a>
          <br />
          <br />
          <b>Workshops:</b>
          <br />
          Infos folgen demnächst
        </div>
        <p>
          An „OZG-Security-Challenge 2023“ können OZG-Dienstverantwortliche bis
          zum 31. Oktober 2023 teilnehmen. Herzstück der Challenge ist der
          OZG-Security-Challenge-Schnelltest, welcher den Umsetzungsgrad von
          sechs ausgewählten IT-Sicherheitsmaßnahmen auf den eingegebenen
          Webseiten darstellt, Potenziale zur weiteren Stärkung der
          IT-Sicherheit aufzeigt und Hilfestellung bei deren Umsetzung gibt.
        </p>
        <p>
          Der Schnelltest ist in einem geschützten Bereich exklusiv für die
          OZG-Umsetzungsverantwortlichen in Bund, Ländern und Kommunen
          zugänglich. Alle teilnehmenden Behörden erhalten einen individuellen,
          tokenbasierten Zugang zum Schnellstet, um ihre Onlinedienste auf die
          ausgewählten IT-Sicherheitsmaßnahmen zu prüfen.
        </p>
        <p>
          Im Schnelltest wird die Umsetzung folgender sechs
          IT-Sicherheitsmaßnahmen angezeigt:
        </p>
        <ul>
          <li>
            Responsible Disclosure: Meldung von Schwachstellen vor
            Veröffentlichung
          </li>
          <li>
            Transport Layer Security (TLS) 1.3: Aktuelle Verschlüsselung der
            Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst
          </li>
          <li>
            TLS 1.0 & 1.1 deaktivieren: Veraltete Verschlüsselung deaktivieren
          </li>
          <li>
            HTTP Strict Transport Security (HSTS): Sicherstellung
            verschlüsselter Kommunikation zwischen Bürgerinnen, Bürgern und
            OZG-Dienst
          </li>
          <li>
            Domain Name System Security Extensions (DNSSEC): Sichere Verknüpfung
            von Internetadresse und Serveradresse
          </li>
          <li>
            Resource Public Key Infrastructure (RPKI): Schutz vor nicht
            autorisierter Umleitung von Datenverkehr
          </li>
        </ul>
        <p>
          Die Ergebnisse des Schnelltests werden durch Erklärungen und Hinweise
          zur Umsetzung der IT-Sicherheitsmaßnahmen ergänzt.
        </p>
        <p>
          Das BMI begleitet die Teilnehmenden mit Angeboten in Form von
          detaillierten Informationen zur Umsetzung, Workshops oder
          Sprechstunden für eine individuelle Beratung. Zudem senden wir Ihnen
          den Zugang zum Dashboard, welches Sie für einen Gesamtüberblick mit
          Ihren Domains befüllen können.
        </p>
        <p>
          Die Teilnehmenden können ihre Teilnahme an der Challenge durch den
          Sticker der OZG-Security-Challenge 2023 demonstrieren: Der weiße
          Sticker verdeutlicht die Teilnahme an der Challenge, bei erfolgreicher
          Implementierung und Abschluss der Challenge erhalten die Teilnehmenden
          auf Anfrage zudem den goldenen Sticker.
        </p>
        <div className="flex flex-wrap sm:gap-2 md:gap-8">
          <Image
            src={"/assets/challenge_sticker.svg"}
            width={250}
            height={250}
            className="py-5"
            alt="Sticker"
          />
          <Image
            src={"/assets/challenge_sticker_gold.svg"}
            width={250}
            height={250}
            className="py-5"
            alt="Sticker"
          />
        </div>
        <p>
          Die Challenge gilt dann als erfolgreich umgesetzt, wenn alle sechs
          IT-Sicherheitsmaßnahmen in den jeweiligen OZG-Onlinediensten
          implementiert wurden.
        </p>
        <h2>Die IT-Sicherheitsmaßnahmen im Detail</h2>
        <p>
          Im Zuge der OZG-Security-Challenge werden die Umsetzungsstände von den
          oben bereits kurz aufgeführten sechs IT-Sicherheitsmaßnahmen
          dargestellt. Diese wurden ausgewählt, da sie einen wichtigen Beitrag
          zur sicheren OZG-Umsetzung leisten. Mit der Erfüllung der sechs
          IT-Sicherheitsmaßnahmen kann das Sicherheitsniveau der Portale und
          Webseiten der öffentlichen Verwaltung noch weiter gesteigert werden.
        </p>
        <p>
          Diese sechs IT-Sicherheitsmaßnahmen sind aber nicht abschließend zu
          betrachten, sondern stellen einen ersten Ansatz zur Standardisierung
          der IT-Sicherheit im OZG-Kontext dar. Die Umsetzung von IT-Sicherheit
          ist ein Prozess, der kontinuierlich fortgeführt werden muss. So ist
          auch geplant, den Schnelltest weiter auszubauen und sukzessive um
          weitere Kriterien zu erweitern. Der Schnelltest wird daher auch nach
          der Challenge weiterhin zur Verfügung stehen.
        </p>
        <h2>
          Hintergrund: Die Bedeutung der IT-Sicherheit in der öffentlichen
          Verwaltung steigt
        </h2>
        <p>
          Schon zu Beginn der Umsetzung des Onlinezugangsgesetzes (OZG) war
          klar, dass die Verwaltungsdigitalisierung nur erfolgreich sein kann,
          wenn sie eine wirkliche Verbesserung für Alle mit sich bringt und die
          konzipierten Onlinedienste auch akzeptiert und genutzt werden. Daher
          gilt es, das Vertrauen der Bürgerinnen, Bürger und Unternehmen in die
          Onlinedienste zu stärken.
        </p>
        <p>
          Die Relevanz der Informationssicherheit wird daher auch im{" "}
          <Link
            rel="noopener noreferrer"
            target={"_blank"}
            href={
              "https://www.bundesregierung.de/breg-de/service/gesetzesvorhaben/koalitionsvertrag-2021-1990800"
            }
            prefetch={false}
          >
            Koalitionsvertrag
          </Link>{" "}
          sowie in der{" "}
          <Link
            href="https://www.bundesregierung.de/breg-de/themen/digitaler-aufbruch/digitalstrategie-2072884"
            rel="noopener noreferrer"
            target={"_blank"}
            prefetch={false}
          >
            Digitalstrategie der Bundesregierung
          </Link>{" "}
          betont. Aufgrund der Schnelllebigkeit und Komplexität des Themas wird
          die IT-Sicherheit der öffentlichen Verwaltung fortlaufend an externe
          Gegebenheiten angepasst, beispielsweise durch die Aufnahme von
          „Responsible Disclosure“ in die „Einer für Alle“
          (EfA)-Mindestanforderungen 2.0 (Stand November 2022). Eine
          flächendeckende Anwendung der neuesten IT-Sicherheitsmaßnahmen ist
          derzeit noch nicht überall gegeben.
        </p>
        <p>
          Die OZG-Security-Challenge setzt hier an und regt zur Steigerung der
          Bekanntheit der IT-Sicherheitsmaßnahmen an und unterstützt die
          OZG-Dienstverantwortlichen durch ein umfassendes Sprechstunden- und
          Kommunikationsangebot bei deren Umsetzung.
        </p>
      </div>
    </Article>
  );
};

export default InfoContent;
