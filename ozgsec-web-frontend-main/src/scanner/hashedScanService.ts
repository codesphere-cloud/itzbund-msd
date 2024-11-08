import { PrismaClient } from "@prisma/client";
import { getLogger } from "../services/logger";
import {
  DetailedTarget,
  ISarifResponse,
  ISarifScanErrorResponse,
  ISarifScanSuccessResponse,
} from "../types";
import {
  getHostnameFromUri,
  getPathFromUri,
  getUriWithHashedHostname,
  sanitizeURI,
} from "../utils/common";
import { DTO } from "../utils/server";
import {
  MessageBrokerClient,
  ScanService,
  ScanTargetOptions,
} from "./scanService";

const logger = getLogger(__filename);

/**
 * This is an extension for the scanner service.
 * HashedScanService hashes the uris and masks the ip address for further processes after scanning.
 * The response returned form the service is an unmasked result.
 */

export class HashedScanService extends ScanService {
  constructor(messageBrokerClient: MessageBrokerClient, db: PrismaClient) {
    super(messageBrokerClient, db);
  }

  // wont save the result to the database
  // use scanTargetRPC instead
  public async scanRPC(
    requestId: string,
    target: string,
    options: ScanTargetOptions,
  ): Promise<ISarifResponse> {
    let result = await super.scanRPC(requestId, target, options);
    result = await this.hashURIInSarifResponse(result, target);
    return result;
  }

  // abstracts the whole app functionality for rpc calls.
  // it makes sure, that the database is in a consistent state.
  // do not use the response to update the database.
  public async scanTargetRPC(
    requestId: string,
    target: string | null,
    options: ScanTargetOptions,
  ): Promise<
    | [DTO<ISarifScanSuccessResponse>, DTO<DetailedTarget>]
    | [DTO<ISarifScanErrorResponse>, undefined]
  > {
    const sanitizedURI = sanitizeURI(target);
    if (!sanitizedURI) {
      throw new Error("invalid target");
    }
    const hashedUriForDBReference =
      await getUriWithHashedHostname(sanitizedURI);

    const responseResult = await this.scanTargetRPCImpl(
      requestId,
      sanitizedURI,
      options,
      hashedUriForDBReference,
    );

    const resetHashedObjects = this.resetHashesForResponse(
      sanitizedURI,
      responseResult[0],
      responseResult[1],
    );

    return [
      resetHashedObjects.responseResult,
      resetHashedObjects.responseDetailedTarget,
    ] as
      | [DTO<ISarifScanSuccessResponse>, DTO<DetailedTarget>]
      | [DTO<ISarifScanErrorResponse>, undefined];
  }

  private async scanTargetRPCImpl(
    requestId: string,
    sanitizedURI: string,
    options: ScanTargetOptions,
    hashedUriForDBReference: string,
  ): Promise<
    | [DTO<ISarifScanSuccessResponse>, DTO<DetailedTarget>]
    | [DTO<ISarifScanErrorResponse>, undefined]
  > {
    logger.debug(
      { requestId },
      `received request to scan site: ${hashedUriForDBReference}`,
    );

    if (!options.refreshCache) {
      // check if it exists already inside the cache
      const responseResult = await super.getReportFromCache(
        requestId,
        hashedUriForDBReference,
      );

      if (responseResult) {
        return responseResult;
      }
    }
    const result: ISarifScanSuccessResponse | ISarifScanErrorResponse =
      await this.scanRPC(requestId, sanitizedURI, options);

    const detailedTarget: DTO<DetailedTarget> | undefined =
      await this.handleScanResponse(requestId, result, options, 40_000);

    return [result, detailedTarget] as
      | [DTO<ISarifScanSuccessResponse>, DTO<DetailedTarget>]
      | [DTO<ISarifScanErrorResponse>, undefined];
  }

  private async hashURIInSarifResponse(
    result: ISarifResponse,
    sanitizedURI: string,
  ): Promise<ISarifResponse> {
    const copiedResult: ISarifResponse = JSON.parse(JSON.stringify(result));

    for (const run of copiedResult.runs) {
      const properties = run.properties;
      properties.target = await getUriWithHashedHostname(sanitizedURI);
      properties.sut = await getUriWithHashedHostname(properties.sut);
      const ipParts = properties.ipAddress.split(".");
      properties.ipAddress = `${ipParts[0]}.${ipParts[1]}.0.0`;
    }
    return copiedResult;
  }

  private resetHashesInSarifResponse(
    result: ISarifResponse,
    sanitizedURI: string,
  ): ISarifResponse {
    const copiedResult: ISarifResponse = JSON.parse(JSON.stringify(result));

    for (const run of copiedResult.runs) {
      const properties = run.properties;
      properties.target = sanitizedURI;
      properties.sut =
        getHostnameFromUri(sanitizedURI) + getPathFromUri(properties.sut);
    }
    return copiedResult;
  }

  private resetHashesInDetailedTarget(
    detailedTarget: DTO<DetailedTarget>,
    notHashedResult: ISarifResponse,
    sanitizedURI: string,
  ): DTO<DetailedTarget> {
    return {
      ...detailedTarget,
      uri: sanitizedURI,
      details: notHashedResult,
    };
  }

  private resetHashesForResponse(
    sanitizedURI: string,
    result: ISarifResponse,
    detailedTarget: DTO<DetailedTarget> | undefined,
  ) {
    const responseResult = this.resetHashesInSarifResponse(
      result,
      sanitizedURI,
    );
    const responseDetailedTarget = !detailedTarget
      ? detailedTarget
      : this.resetHashesInDetailedTarget(
          detailedTarget,
          responseResult,
          sanitizedURI,
        );
    return { responseResult, responseDetailedTarget };
  }
}
