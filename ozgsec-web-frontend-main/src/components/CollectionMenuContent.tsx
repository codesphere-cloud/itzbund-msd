import { faCheck } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import DropdownMenuCheckboxItem from "./common/DropdownMenuCheckboxItem";

interface Props<T extends { id: number; title: string; color: string }> {
  collections: {
    [collectionId: string]: T;
  };
  selectedCollections?: number[];
  onCollectionClick: (collection: T) => void;
}
function CollectionMenuContent<
  T extends { id: number; title: string; color: string },
>(props: Props<T>) {
  return (
    <>
      {Object.values(props.collections ?? {}).map((collection, i, arr) => {
        const selected =
          props.selectedCollections !== undefined &&
          props.selectedCollections.includes(+collection.id);

        return (
          <DropdownMenuCheckboxItem
            checked={selected}
            Icon={<FontAwesomeIcon icon={faCheck} />}
            onCheckedChange={() => props.onCollectionClick(collection)}
            key={collection.id}
          >
            {collection.title}
          </DropdownMenuCheckboxItem>
        );
      })}
    </>
  );
}

export default CollectionMenuContent;
