export enum HSTSValidationError {
  MissingHeader = "missingHeader",
  MissingMaxAge = "missingMaxAge",
}

export enum HSTSRecommendation {
  MissingIncludeSubDomains = "missingIncludeSubDomains",
}

export enum ContentSecurityPolicyValidationError {
  MissingHeader = "missingHeader",
  MissingDefaultSrc = "missingDefaultSrc",
}
