import React from "react";
import useCheckbox from "../hooks/useCheckbox";
import useInput from "../hooks/useInput";
import useRequest from "../hooks/useRequest";
import { clientHttpClient } from "../services/clientHttpClient";
import { emailRegex } from "../utils/common";
import Checkbox from "./common/Checkbox";
import FormInput from "./common/FormInput";
import Button from "./common/Button";

const Subscribe = () => {
  const email = useInput();
  const check = useCheckbox();

  const submitRequest = useRequest();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email.value || !emailRegex.test(email.value)) {
      return;
    }

    if (!check.value) {
      return;
    }

    const data = {
      email: email.value,
      check: check.value,
    };

    try {
      await submitRequest.run(
        clientHttpClient("/api/v1/subscribe", crypto.randomUUID(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(data),
        }),
      );
      email.onChange("");
    } catch {}
  };
  return (
    <div className="p-4 text-white bg-deepblue-400">
      <p>
        Melden Sie sich jetzt für die OZG-Security-Challenge an und erhalten Sie
        exklusive Infos:
      </p>
      <form onSubmit={handleSubmit} className="text-black mt-5">
        <div className="">
          <FormInput
            type="email"
            placeholder="Geben Sie hier Ihre E-Mail Adresse ein"
            {...email}
            label="E-Mail Adresse"
          />
          <div className="flex flex-row mt-4 justify-between">
            <div className="text-white flex-row flex mr-5">
              <div>
                <Checkbox {...check} />
              </div>
              <p
                onClick={() => check.onChange()}
                className="ml-2 cursor-pointer"
              >
                Mit dem Absenden des Formulars stimme ich der Verarbeitung
                meiner E-Mail Adresse gemäß der&nbsp;
                <a
                  rel="noreferrer"
                  target="_blank"
                  className="underline"
                  href="https://www.bmi.bund.de/DE/service/datenschutz/datenschutz_node.html"
                >
                  Datenschutzerklärung
                </a>
                , sowie dem Erhalt des OZG-Security-Challenge Newsletters zu.
              </p>
            </div>
            <div className="whitespace-nowrap">
              <Button
                disabled={!check.checked || !emailRegex.test(email.value)}
                loading={false}
                type="submit"
              >
                Anmelden
              </Button>
            </div>
          </div>
        </div>
        {submitRequest.isError && (
          <div className="text-red-500 text-right mt-2">
            Ein Fehler ist aufgetreten. Bitte versuchen Sie es später noch mal.
          </div>
        )}
        {submitRequest.isSuccess && (
          <div className="text-lightning-500 text-right mt-2">
            Vielen Dank für Ihre Anmeldung.
          </div>
        )}
      </form>
    </div>
  );
};

export default Subscribe;
