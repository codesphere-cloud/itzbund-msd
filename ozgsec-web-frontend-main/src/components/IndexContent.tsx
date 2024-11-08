"use client";

import Image from "next/image";
import { useSearchParams } from "next/navigation";
import { FunctionComponent, useEffect } from "react";
import { useQuicktest } from "../hooks/useQuicktest";
import { classNames } from "../utils/common";
import { useGlobalStore } from "../zustand/global";
import ReleasePlaceHolder from "./ReleasePlaceholder";
import ResultEnvelope from "./ResultEnvelope";
import ScanPageHero from "./ScanPageHero";

interface Props {
  displayNotAvailable: boolean;
}
const IndexContent: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  const searchParams = useSearchParams();
  const {
    website,
    setWebsite,
    scanRequest,
    refreshRequest,
    report,
    dateString,
    testAmount,
    handleRefresh,
    onSubmit,
  } = useQuicktest(searchParams?.get("s"));

  const store = useGlobalStore();

  useEffect(() => {
    store.setHideLogin(displayNotAvailable);
  }, [displayNotAvailable]);

  if (displayNotAvailable) {
    return <ReleasePlaceHolder />;
  }

  return (
    <div className="flex relative md:py-10 flex-col w-full justify-center">
      <div className="relative">
        <Image
          className="absolute hidden lg:inline top-0 right-0"
          width={500}
          height={225}
          priority
          src={"/assets/Adler_Ausschnitt_1.svg"}
          alt="OZG-Logo"
        />
        <div className="container relative z-10">
          <ScanPageHero
            onSubmit={onSubmit}
            setWebsite={setWebsite}
            website={website}
            scanRequest={scanRequest}
          />
          <div className={classNames(report && "my-10")}>
            <ResultEnvelope
              report={report}
              dateString={dateString}
              handleRefresh={handleRefresh}
              refreshRequest={refreshRequest}
              testAmount={testAmount}
            />
          </div>
          {/*<div className="bg-deepblue-400 justify-center mx-5 md:mx-0 mb-5 flex flex-col md:flex-row md:justify-between items-center text-white mt-5 p-4">
        <p>Die OZG-Security-Challenge: Hintergrundinfos und Vieles mehr.</p>
        <a
          title="Mehr Informationen zur OZG-Security-Challenge 2023"
          target={"_blank"}
          rel={"noopener noreferrer"}
          className="bg-lightning-500 hover:bg-lightning-900 mt-5 md:mt-0 transition-all px-5 py-2 text-deepblue-500 text-center font-bold"
          href="www.onlinezugangsgesetz.de/ozgsec"
        >
          Mehr erfahren
        </a>
  </div>*/}
        </div>
      </div>
    </div>
  );
};

export default IndexContent;
