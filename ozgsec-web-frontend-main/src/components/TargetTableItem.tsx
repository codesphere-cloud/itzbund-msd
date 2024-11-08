import {
  faEllipsisVertical,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Collection, Target } from "@prisma/client";
import { toUnicode } from "punycode";
import { FunctionComponent, useMemo } from "react";
import { useIsGuest } from "../hooks/useIsGuest";
import useLoading from "../hooks/useLoading";
import {
  AccessiblityInspectionType,
  DomainInspectionType,
  HeaderInspectionType,
  NetworkInspectionType,
  OrganizationalInspectionType,
  TLSInspectionType,
} from "../scanner/scans";
import { getCheckDescription, titleMapper } from "../messages";
import { DetailedTarget, FeatureFlag } from "../types";
import { classNames, toGermanDate } from "../utils/common";
import { DTO } from "../utils/server";
import { kind2CheckResult } from "../utils/view";
import Checkbox from "./common/Checkbox";
import ResultIcon from "./ResultIcon";
import Tooltip from "./common/Tooltip";
import DropdownMenuItem from "./common/DropdownMenuItem";
import Menu from "./common/Menu";
import Spinner from "./common/Spinner";
import Link from "next/link";
import CollectionPill from "./CollectionPill";
import { useIsFeatureEnabled } from "../hooks/useFeatureEnabled";
import CollectionMenuContent from "./CollectionMenuContent";
import SubMenu from "./common/SubMenu";

interface Props {
  onSelect: (target: DTO<DetailedTarget>) => void;
  target: DTO<DetailedTarget> & { collections?: number[] };
  classNames?: string;
  selected: boolean;
  scanRequest: ReturnType<typeof useLoading>;
  scan: (uri: string) => void;
  destroy: (uri: string) => void;
  onToggleCollection: (collection: DTO<Collection>) => void;
  collections: { [collectionId: string]: DTO<Collection> };
}

const infoMessage = (target: DTO<Target>) => {
  return target.lastScan !== null
    ? `Letzter Scan: ${toGermanDate(new Date(target.lastScan))}${
        target.errorCount !== null && target.errorCount > 0
          ? ` (${target.errorCount} Fehler)`
          : ""
      }${
        target.errorCount !== null && target.errorCount >= 5
          ? " target wird nicht mehr automatisiert gescanned, da 5 Fehler überschritten wurden"
          : ""
      }`
    : "Noch nicht gescannt";
};
const TargetTableItem: FunctionComponent<Props> = ({
  onSelect,
  target,
  classNames: clNames,
  selected,
  scanRequest,
  scan,
  destroy,
  collections,
  onToggleCollection,
}) => {
  const isGuest = useIsGuest();
  const collectionEnabled = useIsFeatureEnabled(FeatureFlag.collections);
  const detailsMap = useMemo(
    () =>
      Object.fromEntries(
        target.details?.runs[0].results.map((r) => [r.ruleId, r]) ?? [],
      ),
    [target],
  );
  return (
    <>
      <tr
        onClick={() => onSelect(target)}
        className={classNames(
          "cursor-pointer relative lg:static ´ mt-3 grid-cols-8 lg:mt-0 grid lg:table-row flex-wrap",
          target.errorCount !== null && target.errorCount >= 5
            ? "line-through"
            : "",
          clNames,
          Object.keys(collections).length === 0 ? "rounded-b-md" : "",
        )}
      >
        <td
          className="px-4 py-2
         lg:p-2 absolute lg:static top-2 bg-dunkelblau-100 lg:bg-transparent pr-0"
        >
          {!isGuest && (
            <div className="flex flex-row h-full items-center">
              <Checkbox onChange={() => onSelect(target)} checked={selected} />
            </div>
          )}
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8  bg-dunkelblau-100  text-white lg:text-textblack lg:bg-transparent">
          <div className="flex pl-10 lg:pl-0 flex-row">
            <Link
              target={"_blank"}
              href={`//${target.uri}`}
              onClick={(e) => e.stopPropagation()}
              rel="noopener"
              title={target.uri}
              className="text-ellipsis max-w-xs block"
            >
              {toUnicode(target.uri)}
            </Link>
            <div className="hidden lg:inline ml-2">
              <Tooltip tooltip={infoMessage(target)}>
                <FontAwesomeIcon
                  className="opacity-50"
                  icon={faQuestionCircle}
                />
              </Tooltip>
            </div>
          </div>
          {collectionEnabled && (
            <div className="flex flex-row gap-2">
              {target.collections?.map((c) => {
                const col = collections[c.toString()];
                return <CollectionPill selected={true} key={col.id} {...col} />;
              })}
            </div>
          )}
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row justify-between items-center">
          <span className="lg:hidden text-sm opacity-75">
            {titleMapper[OrganizationalInspectionType.ResponsibleDisclosure]}
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              OrganizationalInspectionType.ResponsibleDisclosure,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[OrganizationalInspectionType.ResponsibleDisclosure]
                  ?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row items-center justify-between">
          <span className="lg:hidden text-sm opacity-75">
            {titleMapper[TLSInspectionType.TLSv1_3]}
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              TLSInspectionType.TLSv1_3,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[TLSInspectionType.TLSv1_3]?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row justify-between items-center">
          <span className="lg:hidden text-sm opacity-75">
            {titleMapper[TLSInspectionType.DeprecatedTLSDeactivated]}
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              TLSInspectionType.DeprecatedTLSDeactivated,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[TLSInspectionType.DeprecatedTLSDeactivated]?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row justify-between items-center">
          <span className="lg:hidden text-sm opacity-75">
            {titleMapper[HeaderInspectionType.HSTS]}
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              HeaderInspectionType.HSTS,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[HeaderInspectionType.HSTS]?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row justify-between items-center">
          <span className="lg:hidden text-sm opacity-75">
            {titleMapper[DomainInspectionType.DNSSec]}
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              DomainInspectionType.DNSSec,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[DomainInspectionType.DNSSec]?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td className="px-4 py-2 lg:p-2 col-span-8 flex lg:table-cell flex-row justify-between items-center">
          <span className="lg:hidden text-sm opacity-75">
            {
              titleMapper[
                AccessiblityInspectionType.ProvidesEnglishWebsiteVersion
              ]
            }
          </span>
          <Tooltip
            tooltip={getCheckDescription(
              target.details,
              AccessiblityInspectionType.ProvidesEnglishWebsiteVersion,
            )}
          >
            <ResultIcon
              checkResult={kind2CheckResult(
                detailsMap[
                  AccessiblityInspectionType.ProvidesEnglishWebsiteVersion
                ]?.kind,
              )}
            />
          </Tooltip>
        </td>
        <td
          className="text-right -top-1 -right-2 px-4 py-2 lg:p-2 absolute lg:static"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex flex-row justify-end">
            <Menu
              Button={
                <div className="px-4 py-2 lg:p-2 text-white lg:text-textblack h-8 w-8 flex flex-row h-full items-center justify-center">
                  {scanRequest.key === target.uri && scanRequest.isLoading ? (
                    <div className="absolute">
                      <Spinner />
                    </div>
                  ) : (
                    <FontAwesomeIcon icon={faEllipsisVertical} />
                  )}
                </div>
              }
              Menu={
                <>
                  <DropdownMenuItem
                    loading={
                      scanRequest.key === target.uri && scanRequest.isLoading
                    }
                    onClick={() => scan(target.uri)}
                  >
                    <div>
                      <div>Erneut scannen</div>
                      {scanRequest.key === target.uri && (
                        <span className="block text-red-500 text-sm">
                          {scanRequest.errorMessage}
                        </span>
                      )}
                    </div>
                  </DropdownMenuItem>

                  {collectionEnabled && (
                    <>
                      {Object.keys(collections).length > 0 ? (
                        <SubMenu
                          Button={<div>Gruppen</div>}
                          Menu={
                            <CollectionMenuContent
                              collections={collections}
                              selectedCollections={target.collections ?? []}
                              onCollectionClick={(collection) =>
                                onToggleCollection(collection)
                              }
                            />
                          }
                        />
                      ) : (
                        <Link
                          className="hover:no-underline block"
                          href={"/dashboard/collections"}
                        >
                          <DropdownMenuItem>Gruppe erstellen</DropdownMenuItem>
                        </Link>
                      )}
                    </>
                  )}
                  <DropdownMenuItem onClick={() => destroy(target.uri)}>
                    Löschen
                  </DropdownMenuItem>
                </>
              }
            />
          </div>
        </td>
      </tr>
    </>
  );
};

export default TargetTableItem;
