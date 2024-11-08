import ozgLogo from './assets/ozg-logo.svg';

const Footer = () => {
  return (
    <footer className="bg-bund relative pb-10">
    
    <div className="tw-container flex-wrap flex justify-end flex-row pt-10 pb-5">
      <img
        width={140}
        height={61}
        src={ozgLogo}
        alt="OZG Logo"
      />
    </div>
    <div className="tw-container pt-10 text-xs">
      <div className="lg:flex text-white pt-10 border-t justify-between">
        <div className="flex flex-wrap gap-2 items-center flex-row">
          <span>
            <a
              aria-label="Impressum öffnen"
              href={"//ozgsec.de/impressum"}
              className="cursor-pointer text-white uppercase font-medium p-2 hover:text-white"
              type="button"
            >
              Impressum
            </a>
          </span>
          <span>
            <a
              aria-label="Datenschutzerklärung öffnen"
              href="//ozgsec.de/datenschutz"
              className="cursor-pointer uppercase font-medium text-white p-2 hover:text-white"
              type="button"
            >
              Datenschutz
            </a>
          </span>
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
