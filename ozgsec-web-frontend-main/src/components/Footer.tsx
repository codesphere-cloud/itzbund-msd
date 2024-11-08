import Image from "next/image";
import { FunctionComponent } from "react";
import LinkWithQuery from "./common/LinkWithQuery";
import ScrollUpButton from "./ScrollUpButton";
import { featureFlags } from "../feature-flags";

const Footer: FunctionComponent = () => {
  let imprintUrl: string = process.env.NEXT_PUBLIC_IMPRINT_URL || "/impressum";

  return (
    <footer className="bg-bund relative pb-10">
      <div className="flex flex-row justify-center pt-10">
        <ScrollUpButton />
      </div>
      <div className="container flex-wrap flex justify-end flex-row pt-10 pb-5">
        <Image
          width={140}
          height={66}
          src={"/assets/ozg-logo.svg"}
          alt="OZG Logo"
        />
      </div>
      <div className="container pt-10 text-xs">
        <div className="lg:flex text-white pt-10 border-t justify-between">
          <div className="flex flex-wrap gap-2  flex-row">
            <LinkWithQuery
              aria-label="Impressum öffnen"
              href={imprintUrl}
              className="cursor-pointer text-white uppercase font-medium p-2 hover:text-white"
              type="button"
            >
              Impressum
            </LinkWithQuery>

            {featureFlags.dashboardEnabled && (
              <LinkWithQuery
                aria-label="Datenschutzerklärung öffnen"
                href="/datenschutz"
                className="cursor-pointer uppercase font-medium text-white p-2 hover:text-white"
                type="button"
              >
                Datenschutz
              </LinkWithQuery>
            )}

            <span>
              <a
                href="https://www.onlinezugangsgesetz.de/"
                rel="noopener noreferrer"
                className="p-2 uppercase font-medium text-white block hover:text-white"
                target={"_blank"}
              >
                Onlinezugangsgesetz.de
              </a>
            </span>
          </div>
          <div className="flex flex-wrap flex-row mb-0">
            <span className="mt-5 py-2 sm:mt-0">
              <a
                href="https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec"
                rel="noopener noreferrer"
                className="p-2 uppercase font-medium text-white block hover:text-white"
                target={"_blank"}
              >
                Code des Projekts auf Open CoDE
              </a>
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
