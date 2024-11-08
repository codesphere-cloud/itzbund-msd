import { faEnvelope, faPhone } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import AddDomainForm from "../components/AddDomainForm";
import { clientHttpClient } from "../services/clientHttpClient";
import Button from "./common/Button";
import Modal from "./common/Modal";
import { useRouter } from "next/navigation";

const EmptyDashboardNotice = () => {
  const [isOpen, setIsOpen] = useState(false);
  const router = useRouter();

  const handleAddRecord = async (target: string) => {
    const res = await clientHttpClient(`/api/v1/targets`, crypto.randomUUID(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ target }),
    });

    if (!res.ok) {
      throw res;
    }
    router.refresh();
  };

  const handleFileFormSubmit = async (files: File[]) => {
    const formData = new FormData();
    files.forEach((file) => {
      formData.append("files", file);
    });

    const res = await clientHttpClient("/api/v1/targets", crypto.randomUUID(), {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      throw res;
    }
  };

  return (
    <>
      <div>
        <div className="grid text-base grid-cols-1 md:grid-cols-2 gap-8">
          <div className="text-left col-span-2">
            <h2 className="text-xl font-bold ">
              Es sind noch keine Domains für Ihr Dashboard hinterlegt
            </h2>
            <p className="mt-6 opacity-75">
              Herzlich willkommen auf Ihrem Dashboard. Hier sehen Sie täglich
              erstellte Statistiken zu Ihren Domains. Ihnen werden standardmäßig
              die Ergebnisse der Top 100.000 .de sowie globalen Domains als
              Referenz angezeigt.
            </p>
            <p className="mt-6  opacity-75">
              Bei Fragen wenden Sie sich gerne an unseren E-Mail-Support oder
              besuchen Sie unsere Sprechstunde.
            </p>
          </div>
          <div className="grid gap-x-8 gap-y-3">
            <div key="sprechstunde" className="flex gap-x-3">
              <FontAwesomeIcon
                className="h-7 w-7 flex-none mt-2"
                icon={faPhone}
              />
              <span>
                <a href="tel:+4920878012422" className="underline">
                  0208 78012422
                </a>
                <br />
                Sprechstunde (Mo. 10:00 - 12:00 Uhr)
              </span>
            </div>
            <div key="one-pager" className="flex gap-x-3">
              <FontAwesomeIcon
                className="h-7 w-7 flex-none mt-2"
                icon={faEnvelope}
              />
              <span>
                <a
                  href="mailto:ozgsec@bmi.bund.de"
                  className="underline whitespace-nowrap"
                >
                  ozgsec@bmi.bund.de
                </a>
                <br />
                E-Mail Support
              </span>
            </div>
          </div>
        </div>
        <div className="mt-5 text-base flex flex-col md:flex-row gap-8 md:items-center">
          <Button type="button" loading={false} onClick={() => setIsOpen(true)}>
            Domains hinzufügen
          </Button>
        </div>
      </div>
      <Modal
        title="Domains hinzufügen"
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
      >
        <AddDomainForm
          onNewDomain={handleAddRecord}
          onFileFormSubmit={handleFileFormSubmit}
        />
      </Modal>
    </>
  );
};

export default EmptyDashboardNotice;
