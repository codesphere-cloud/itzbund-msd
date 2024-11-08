import ip from "ip";

const emailRegex =
  /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
export const isValidEmail = (email: string): boolean => {
  return emailRegex.test(email);
};

export const isValidIp = (ipAddress: string): boolean => {
  return ip.isV4Format(ipAddress);
};

export const isValidMask = (mask: string): boolean => {
  const prefixLength = parseInt(mask);
  return prefixLength >= 0 && prefixLength <= 32;
};

/* 
  The domain name should be a-z or A-Z or 0-9 and hyphen (-).
  The domain name should be between 1 and 63 characters long.
  The domain name should not start or end with a hyphen(-) (e.g. -geeksforgeeks.org or geeksforgeeks.org-).
  The last TLD (Top level domain) must be at least two characters and a maximum of 6 characters.
  The domain name can be a subdomain (e.g. write.geeksforgeeks.org).
  
  Ref: https://www.geeksforgeeks.org/how-to-validate-a-domain-name-using-regular-expression/
  */

// 7 characters as TLD is valid as well: https://en.wikipedia.org/wiki/Top-level_domain#Internationalized_top-level_domains
const hostnameRegex = new RegExp(
  /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/,
);

export const isValidHostname = (uri: string): boolean => {
  return hostnameRegex.test(uri);
};
