import { useSearchParams } from "next/navigation";
import { FormEvent, FunctionComponent, useState } from "react";
import useLoading from "../hooks/useLoading";
import Button from "./common/Button";

import FormInput from "./common/FormInput";

const TargetOverviewForm: FunctionComponent<{
  onSearch: (search: string) => Promise<void>;
}> = ({ onSearch }) => {
  const searchParams = useSearchParams();

  const [search, setSearch] = useState(
    (searchParams?.get("search")?.toString() as string) ?? "",
  );
  const searchRequest = useLoading();

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault();
    searchRequest.loading();
    try {
      await onSearch(search);
      searchRequest.success();
    } catch (err) {
      searchRequest.error("Leider ist ein Fehler bei der Suche aufgetreten.");
    }
  };

  return (
    <div>
      <div className="flex gap-2 flex-col md:flex-row items-end">
        <form
          className="flex flex-1 gap-2 w-full flex-col md:flex-row items-end"
          onSubmit={handleSearch}
        >
          <div className="flex-1 w-full">
            <FormInput
              onChange={setSearch}
              label="Suche nach Domains"
              value={search}
              placeholder="example.com"
            />
          </div>
          <div>
            <Button type="submit" loading={searchRequest.isLoading}>
              Suchen
            </Button>
          </div>
        </form>
      </div>
      {!searchRequest.errored && (
        <span className="text-red-500 mt-2">{searchRequest.errorMessage}</span>
      )}
    </div>
  );
};

export default TargetOverviewForm;
