export enum ResponsibleDisclosureValidationError {
  MissingResponsibleDisclosure = "missingResponsibleDisclosure",
  MissingContactField = "missingContactField",
  InvalidExpiresField = "invalidExpiresField",
  Expired = "expired",
  MissingExpiresField = "missingExpiresField",
  WrongMimeType = "wrongMimeType",
}

// invalid means either missing or twice included
export enum ResponsibleDisclosureRecommendation {
  InvalidEncryption = "invalidEncryption",
  InvalidCanonical = "invalidCanonical",
  InvalidPreferredLanguages = "invalidPreferredLanguages",
  MissingPGPSignature = "missingPGPSignature",
}
