import {
  FormEventHandler,
  FunctionComponent,
  useEffect,
  useState,
} from "react";
import useLoading from "../hooks/useLoading";
import { colors } from "../utils/common";
import FormInput from "./common/FormInput";
import Button from "./common/Button";
import Menu from "./common/Menu";

interface Props {
  onCreate: (tag: { title: string; color: string }) => Promise<void>;
}

const CollectionForm: FunctionComponent<Props> = ({ onCreate }) => {
  const createRequest = useLoading();

  const [title, setTitle] = useState("");
  const [color, setColor] = useState(colors[0]);

  useEffect(() => {
    setColor(colors[Math.floor(Math.random() * colors.length)]);
  }, []);

  const handleSubmit: FormEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();
    if (title.length === 0) return;
    createRequest.loading();
    try {
      await onCreate({ title: title, color: color });
      setTitle("");
    } finally {
      createRequest.success();
    }
  };

  return (
    <form
      className="justify-between text-base flex gap-2 flex-wrap flex-row items-end"
      onSubmit={handleSubmit}
    >
      <div className="flex items-end gap-2 flex-1 flex-row">
        <div className="flex-1">
          <FormInput
            value={title}
            placeholder="Gruppe"
            onChange={(e) => setTitle(e)}
            label="Gruppe erstellen"
          />
        </div>
        <Menu
          Button={
            <div
              className="w-14 h-14 cursor-pointer rounded-sm border transition-all hover:opacity-75"
              style={{ backgroundColor: color }}
            />
          }
          Menu={
            <div className="grid grid-cols-3 gap-2 px-1 justify-between items-center">
              {colors.map((color) => (
                <div
                  data-closemenu
                  onClick={() => setColor(color)}
                  key={color}
                  className="h-16 rounded-sm cursor-pointer hover:opacity-50 transition-all "
                  style={{ backgroundColor: color }}
                />
              ))}
            </div>
          }
        />
      </div>
      <Button
        additionalClasses="w-full h-14 sm:w-auto"
        loading={createRequest.isLoading}
        type="submit"
      >
        Erstellen
      </Button>
    </form>
  );
};

export default CollectionForm;
